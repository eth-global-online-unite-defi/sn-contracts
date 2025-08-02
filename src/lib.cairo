use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
use core::poseidon::poseidon_hash_span;

/// Escrow struct to store all escrow details
#[derive(Drop, Serde, starknet::Store)]
pub struct Escrow {
    pub sender: ContractAddress,
    pub receiver: ContractAddress,
    pub amount: u256,
    pub secret_hash: felt252,
    pub timelock: u64,
    pub withdrawn: bool,
    pub cancelled: bool,
    pub token_address: ContractAddress, // 0 address for native ETH
    pub order_id: felt252,
    pub created_at: u64,
}

/// Interface for HTLC Escrow contract
#[starknet::interface]
pub trait IHTLCEscrow<TContractState> {
    
    fn create_htlc_escrow(
        ref self: TContractState,
        token_address: ContractAddress,
        amount: u256,
        secret_hash: felt252,
        timelock: u64,
        receiver: ContractAddress,
        order_id: felt252
    ) -> felt252;
    
    fn withdraw(ref self: TContractState, escrow_id: felt252, secret: felt252);
    
    fn cancel(ref self: TContractState, escrow_id: felt252);
    
    // View functions
    fn get_escrow(self: @TContractState, escrow_id: felt252) -> Escrow;
    
    fn get_escrow_by_order_id(self: @TContractState, order_id: felt252) -> (felt252, Escrow);
    
    fn verify_secret(self: @TContractState, escrow_id: felt252, secret: felt252) -> bool;
    
    fn can_cancel(self: @TContractState, escrow_id: felt252) -> bool;
    
    fn get_contract_balance(self: @TContractState) -> u256;
}

/// HTLC Escrow Contract for Starknet
#[starknet::contract]
mod HTLCEscrow {
    use super::{Escrow, IHTLCEscrow};
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess, Map, StorageMapReadAccess, StorageMapWriteAccess}
    };
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {
        escrows: Map<felt252, Escrow>,
        order_to_escrow_id: Map<felt252, felt252>,
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        EscrowCreated: EscrowCreated,
        EscrowWithdrawn: EscrowWithdrawn,
        EscrowCancelled: EscrowCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct EscrowCreated {
        #[key]
        escrow_id: felt252,
        #[key]
        sender: ContractAddress,
        #[key]
        receiver: ContractAddress,
        amount: u256,
        secret_hash: felt252,
        timelock: u64,
        token_address: ContractAddress,
        order_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct EscrowWithdrawn {
        #[key]
        escrow_id: felt252,
        #[key]
        receiver: ContractAddress,
        secret: felt252,
        order_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct EscrowCancelled {
        #[key]
        escrow_id: felt252,
        #[key]
        sender: ContractAddress,
        order_id: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.owner.write(get_caller_address());
    }

    #[abi(embed_v0)]
    impl HTLCEscrowImpl of IHTLCEscrow<ContractState> {

        fn create_htlc_escrow(
            ref self: ContractState,
            token_address: ContractAddress,
            amount: u256,
            secret_hash: felt252,
            timelock: u64,
            receiver: ContractAddress,
            order_id: felt252
        ) -> felt252 {
            // Validation checks
            assert(!token_address.is_zero(), 'Invalid token address');
            assert(amount > 0, 'Amount cannot be zero');
            assert(timelock > get_block_timestamp(), 'Timelock must be future');
            assert(!receiver.is_zero(), 'Invalid receiver address');
            assert(order_id != 0, 'Order ID cannot be zero');
            
            let sender = get_caller_address();
            let current_time = get_block_timestamp();
            
            // Generate escrow ID using Poseidon hash
            let escrow_id = poseidon_hash_span(
                array![
                    sender.into(),
                    receiver.into(),
                    token_address.into(),
                    amount.low.into(),
                    amount.high.into(),
                    secret_hash,
                    timelock.into(),
                    order_id,
                    current_time.into()
                ].span()
            );
            
            // Check if escrow already exists
            let existing_escrow = self.escrows.read(escrow_id);
            assert(existing_escrow.amount == 0, 'Escrow already exists');
            
            // Check if order ID is already used
            let existing_order_escrow = self.order_to_escrow_id.read(order_id);
            assert(existing_order_escrow == 0, 'Order ID already used');
            
            // Transfer tokens to this contract
            let token = IERC20Dispatcher { contract_address: token_address };
            token.transfer_from(sender, starknet::get_contract_address(), amount);
            
            // Create and store escrow
            let escrow = Escrow {
                sender: sender,
                receiver: receiver,
                amount: amount,
                secret_hash: secret_hash,
                timelock: timelock,
                withdrawn: false,
                cancelled: false,
                token_address: token_address,
                order_id: order_id,
                created_at: current_time,
            };
            
            self.escrows.write(escrow_id, escrow);
            self.order_to_escrow_id.write(order_id, escrow_id);
            
            // Emit event
            self.emit(EscrowCreated {
                escrow_id: escrow_id,
                sender: sender,
                receiver: receiver,
                amount: amount,
                secret_hash: secret_hash,
                timelock: timelock,
                token_address: token_address,
                order_id: order_id,
            });
            
            escrow_id
        }

        fn withdraw(ref self: ContractState, escrow_id: felt252, secret: felt252) {
            let mut escrow = self.escrows.read(escrow_id);
            let caller = get_caller_address();
            
            // Validation checks
            assert(escrow.amount > 0, 'Escrow not found');
            assert(!escrow.withdrawn, 'Already withdrawn');
            assert(!escrow.cancelled, 'Already cancelled');
            assert(caller == escrow.receiver, 'Only receiver can withdraw');
            
            // Verify secret matches hash
            let provided_hash = poseidon_hash_span(array![secret].span());
            assert(provided_hash == escrow.secret_hash, 'Invalid secret');
            
            // Mark as withdrawn
            escrow.withdrawn = true;
            self.escrows.write(escrow_id, escrow);
            
            // Transfer tokens to receiver
            let token = IERC20Dispatcher { contract_address: escrow.token_address };
            token.transfer(escrow.receiver, escrow.amount);
            
            // Emit event
            self.emit(EscrowWithdrawn {
                escrow_id: escrow_id,
                receiver: escrow.receiver,
                secret: secret,
                order_id: escrow.order_id,
            });
        }

        fn cancel(ref self: ContractState, escrow_id: felt252) {
            let mut escrow = self.escrows.read(escrow_id);
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            
            // Validation checks
            assert(escrow.amount > 0, 'Escrow not found');
            assert(!escrow.withdrawn, 'Already withdrawn');
            assert(!escrow.cancelled, 'Already cancelled');
            assert(caller == escrow.sender, 'Only sender can cancel');
            assert(current_time >= escrow.timelock, 'Timelock not expired');
            
            // Mark as cancelled
            escrow.cancelled = true;
            self.escrows.write(escrow_id, escrow);
            
            // Refund tokens to sender
            let token = IERC20Dispatcher { contract_address: escrow.token_address };
            token.transfer(escrow.sender, escrow.amount);
            
            // Emit event
            self.emit(EscrowCancelled {
                escrow_id: escrow_id,
                sender: escrow.sender,
                order_id: escrow.order_id,
            });
        }

        fn get_escrow(self: @ContractState, escrow_id: felt252) -> Escrow {
            self.escrows.read(escrow_id)
        }

        fn get_escrow_by_order_id(self: @ContractState, order_id: felt252) -> (felt252, Escrow) {
            let escrow_id = self.order_to_escrow_id.read(order_id);
            let escrow = self.escrows.read(escrow_id);
            (escrow_id, escrow)
        }

        fn verify_secret(self: @ContractState, escrow_id: felt252, secret: felt252) -> bool {
            let escrow = self.escrows.read(escrow_id);
            let provided_hash = poseidon_hash_span(array![secret].span());
            provided_hash == escrow.secret_hash
        }

        fn can_cancel(self: @ContractState, escrow_id: felt252) -> bool {
            let escrow = self.escrows.read(escrow_id);
            let current_time = get_block_timestamp();
            escrow.amount > 0 && !escrow.withdrawn && !escrow.cancelled && current_time >= escrow.timelock
        }

        fn get_contract_balance(self: @ContractState) -> u256 {
            // Note: This function would need the token address to check balance
            // For now, return 0 as it needs to be implemented per token
            0
        }
    }
}
use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
use core::poseidon::poseidon_hash_span;

/// Escrow struct to store all escrow details
#[derive(Drop, Serde, starknet::Store, Clone)]
pub struct Escrow {
    pub sender: ContractAddress,
    pub receiver: ContractAddress,
    pub amount: u256,
    pub secret_hash: felt252,
    pub timelock: u64,
    pub withdrawn: bool,
    pub cancelled: bool,
    pub token_address: ContractAddress,
    pub order_id: felt252,
    pub created_at: u64,
}

/// Interface for HTLC Escrow contract
#[starknet::interface]
pub trait IHTLCEscrow<TContractState> {
    fn create_escrow(
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
    
    fn get_escrow_balance(self: @TContractState, escrow_id: felt252) -> u256;
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
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // Error constants
    const ESCROW_NOT_FOUND: felt252 = 'Escrow not found';
    const ORDER_ALREADY_USED: felt252 = 'Order already used';
    const ALREADY_WITHDRAWN: felt252 = 'Already withdrawn';
    const ALREADY_CANCELLED: felt252 = 'Already cancelled';
    const INVALID_SECRET: felt252 = 'Invalid secret';
    const INVALID_AMOUNT: felt252 = 'Invalid amount';
    const INVALID_ADDRESS: felt252 = 'Invalid address';
    const INVALID_ORDER_ID: felt252 = 'Invalid order ID';
    const TIMELOCK_NOT_EXPIRED: felt252 = 'Timelock not expired';
    const UNAUTHORIZED_ACCESS: felt252 = 'Unauthorized access';
    const INSUFFICIENT_BALANCE: felt252 = 'Insufficient balance';
    const INVALID_TIMELOCK: felt252 = 'Invalid timelock';

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

        fn create_escrow(
            ref self: ContractState,
            token_address: ContractAddress,
            amount: u256,
            secret_hash: felt252,
            timelock: u64,
            receiver: ContractAddress,
            order_id: felt252
        ) -> felt252 {
            let token = IERC20Dispatcher { contract_address: token_address };

            // Validation checks
            assert(amount > 0, INVALID_AMOUNT);
            assert(timelock > get_block_timestamp(), INVALID_TIMELOCK);
            assert(!receiver.is_zero() && !token_address.is_zero(), INVALID_ADDRESS);
            assert(order_id != 0, INVALID_ORDER_ID);
            
            let sender = get_caller_address();
            
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
                    get_block_timestamp().into()
                ].span()
            );
            
            // Check if escrow already exists
            let existing_escrow = self.escrows.read(escrow_id);
            assert(existing_escrow.amount == 0, 'Escrow already exists');
            
            // Check if order ID is already used
            let existing_order_escrow = self.order_to_escrow_id.read(order_id);
            assert(existing_order_escrow == 0, ORDER_ALREADY_USED);
            
            let sender_balance = token.balance_of(sender);
            assert(sender_balance >= amount, INSUFFICIENT_BALANCE);

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
                created_at: get_block_timestamp(),
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
            // Validation checks
            let caller = get_caller_address();
            let mut escrow = self.escrows.read(escrow_id);
            assert(escrow.amount != 0, ESCROW_NOT_FOUND);
            assert(!escrow.withdrawn, ALREADY_WITHDRAWN);
            assert(!escrow.cancelled, ALREADY_CANCELLED);
            assert(caller == escrow.receiver, UNAUTHORIZED_ACCESS);
            
            //  Verify secret matches hash
            let provided_hash = poseidon_hash_span(array![secret].span());
            assert(provided_hash == escrow.secret_hash, INVALID_SECRET);
            
            // Mark as withdrawn
            escrow.withdrawn = true;
            self.escrows.write(escrow_id, escrow.clone());
            
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
            // let mut escrow = self.escrows.read(escrow_id);
            // let caller = get_caller_address();
            // let current_time = get_block_timestamp();
            
            // // Validation checks
            // assert(escrow.amount > 0, 'Escrow not found');
            // assert(!escrow.withdrawn, 'Already withdrawn');
            // assert(!escrow.cancelled, 'Already cancelled');
            // assert(caller == escrow.sender, 'Only sender can cancel');
            // assert(current_time >= escrow.timelock, 'Timelock not expired');
            
            // // Mark as cancelled
            // escrow.cancelled = true;
            // self.escrows.write(escrow_id, escrow);
            
            // // Refund tokens to sender
            // let token = IERC20Dispatcher { contract_address: escrow.token_address };
            // token.transfer(escrow.sender, escrow.amount);
            
            // // Emit event
            // self.emit(EscrowCancelled {
            //     escrow_id: escrow_id,
            //     sender: escrow.sender,
            //     order_id: escrow.order_id,
            // });
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
            // let escrow = self.escrows.read(escrow_id);
            // let current_time = get_block_timestamp();
            // escrow.amount > 0 && !escrow.withdrawn && !escrow.cancelled && current_time >= escrow.timelock
            true
        }

        fn get_escrow_balance(self: @ContractState, escrow_id: felt252) -> u256 {
            let escrow = self.escrows.read(escrow_id);
            let token = IERC20Dispatcher { contract_address: escrow.token_address };
            token.balance_of(starknet::get_contract_address())
        }
    }
}
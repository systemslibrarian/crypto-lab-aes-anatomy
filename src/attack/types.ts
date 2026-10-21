import type {Block} from '../aes/state';
export type EncryptionOracle=(plaintext:Block)=>Promise<Block>;
export type OwnKeyFactory=()=>Block;
export interface KnownPair{plaintext:Block;ciphertext:Block}
export interface Recovery{kind:'decrypt'|'forge';known:KnownPair[];columns?:bigint[];inverse?:bigint[]|null;rank?:number;operations?:number;candidate:(value:Block)=>Block|null;partial?:boolean}

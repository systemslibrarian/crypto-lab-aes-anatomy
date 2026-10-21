import {mul,inv} from '../gf/gf256';
export type Block=Uint8Array;
export const MC=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]],IMC=[[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]];
export function hex(x:Uint8Array):string{return Array.from(x,b=>b.toString(16).padStart(2,'0')).join('');}
export function parseHex(s:string,lengths:number[]):Uint8Array{if(!lengths.includes(s.length)||!/^[0-9a-f]+$/i.test(s))throw Error(`Expected exactly ${lengths.join(', ')} hexadecimal characters; found ${s.length}. No padding or truncation.`);return Uint8Array.from(s.match(/../g)!,b=>parseInt(b,16));}
export function xor(a:Block,b:Block):Block{return Uint8Array.from(a,(x,i)=>x^b[i]);}
export const equal=(a:Block,b:Block)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
export function shiftRows(a:Block):Block{const b=new Uint8Array(16);for(let r=0;r<4;r++)for(let c=0;c<4;c++)b[r+4*c]=a[r+4*((c+r)%4)];return b;}
export function invShiftRows(a:Block):Block{const b=new Uint8Array(16);for(let r=0;r<4;r++)for(let c=0;c<4;c++)b[r+4*c]=a[r+4*((c+4-r)%4)];return b;}
function transform(a:Block,m:number[][]):Block{const b=new Uint8Array(16);for(let c=0;c<4;c++)for(let r=0;r<4;r++)for(let k=0;k<4;k++)b[r+4*c]^=mul(m[r][k],a[k+4*c]);return b;}
export const mixColumns=(a:Block)=>transform(a,MC),invMixColumns=(a:Block)=>transform(a,IMC);
export function matrixProduct(a:number[][],b:number[][]):number[][]{return a.map(row=>b[0].map((_,j)=>row.reduce((v,x,k)=>v^mul(x,b[k][j]),0)));}
function determinant(m:number[][]):number{const a=m.map(r=>r.slice());let d=1;for(let c=0;c<a.length;c++){let pivot=c;while(pivot<a.length&&a[pivot][c]===0)pivot++;if(pivot===a.length)return 0;[a[c],a[pivot]]=[a[pivot],a[c]];const v=a[c][c];d=mul(d,v);const reciprocal=inv(v).value!;for(let r=c+1;r<a.length;r++){const scale=mul(a[r][c],reciprocal);for(let k=c;k<a.length;k++)a[r][k]^=mul(scale,a[c][k]);}}return d;}
const subsets=(size:number)=>Array.from({length:16},(_,n)=>Array.from({length:4},(_,i)=>i).filter(i=>n&(1<<i))).filter(x=>x.length===size);
export function mdsMinors(){const rows=[];for(let size=1;size<=4;size++)for(const r of subsets(size))for(const c of subsets(size))rows.push({size,rows:r,columns:c,det:determinant(r.map(i=>c.map(j=>MC[i][j])))});return {rows,total:rows.length,nonzero:rows.filter(r=>r.det!==0).length};}
export function dependencies(rounds:number,shift=true,mix=true){let sets=Array.from({length:16},(_,i)=>new Set([i]));for(let k=0;k<rounds;k++){if(shift)sets=Array.from({length:16},(_,i)=>sets[i%4+4*((Math.floor(i/4)+i%4)%4)]);if(mix)sets=Array.from({length:16},(_,i)=>new Set([0,1,2,3].flatMap(r=>[...sets[4*Math.floor(i/4)+r]])));}return sets.map(s=>[...s].sort((a,b)=>a-b));}
export function linearOrder(){let states:Block[]=Array.from({length:128},(_,i)=>{const a=new Uint8Array(16);a[i>>3]=1<<(i&7);return a;});const basis=states.map(x=>x.slice()),checks=[];for(let power=1;power<=8;power++){states=states.map(x=>mixColumns(shiftRows(x)));checks.push({power,identity:states.every((s,i)=>equal(s,basis[i]))});}return checks;}
export function noMixPosition(input:number,rounds=10){const r=input%4,c=Math.floor(input/4);return r+4*((c-r*rounds%4+4)%4);}

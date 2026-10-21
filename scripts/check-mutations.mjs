// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'); process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = title => ['npx', ['playwright','test','e2e/claims.spec.ts','--project=chromium','--grep',title,'--workers=1','--retries=0',...(config ? ['--config',config] : [])]];
const build = ['npm',['run','build']];
const run = ([cmd,args]) => spawnSync(cmd,args,{cwd:root,encoding:'utf8',env:{...process.env,CI:'1'}});
const pass = (cmd,label) => { const r=run(cmd); if(r.status!==0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`); return r; };
const hash = () => { const h=createHash('sha256'); const walk=d=>{for(const e of readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,e.name); if(e.isDirectory())walk(p);else {h.update(p);h.update(readFileSync(p));}}};walk('dist');return h.digest('hex'); };
const cases = [
  {
    "name": "xtime unconditional reduction",
    "changes": [
      {
        "file": "src/gf/gf256.ts",
        "before": "((a&0x80)?0x1b:0)",
        "after": "0x1b"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "FIPS GF256|FIPS all256"
      ]
    ]
  },
  {
    "name": "ShiftRows right",
    "changes": [
      {
        "file": "src/aes/state.ts",
        "before": "a[r+4*((c+r)%4)]",
        "after": "a[r+4*((c+4-r)%4)]"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "FIPS Appendix B"
      ]
    ]
  },
  {
    "name": "MixColumns in final round",
    "changes": [
      {
        "file": "src/aes/cipher.ts",
        "before": "config.mixColumns&&round<Nr",
        "after": "config.mixColumns&&round<=Nr"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "FIPS Appendix B|FIPS 2001 Appendix C"
      ]
    ]
  },
  {
    "name": "AES256 extra SubWord omitted",
    "changes": [
      {
        "file": "src/aes/keyExpansion.ts",
        "before": "Nk===8&&i%Nk===4",
        "after": "Nk===0&&i%Nk===4"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "FIPS Appendix A|FIPS 2001 Appendix C"
      ]
    ]
  },
  {
    "name": "Inverse forward keys",
    "changes": [
      {
        "file": "src/aes/cipher.ts",
        "before": "roundKeys.slice().reverse()",
        "after": "roundKeys.slice()"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Inverse correct",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "Affine second oracle query",
    "changes": [
      {
        "file": "src/attack/affine.ts",
        "before": "offset=pack(ciphertext)^apply(columns,pack(plaintext))",
        "after": "offset=pack(await oracle(zero))^apply(columns,0n)"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noSub",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "Attack receives victim key",
    "changes": [
      {
        "file": "src/attack/affine.ts",
        "before": "injectColumns?:bigint[]):Promise<Recovery>{const own=expand(makeOwnKey())",
        "after": "injectColumns?:bigint[],victimKey?:Block):Promise<Recovery>{const own=expand(victimKey??makeOwnKey())"
      },
      {
        "file": "src/harness.ts",
        "before": "recoverAffine(oracle,makeOwnKey,config,hooks.injectColumns)",
        "after": "recoverAffine(oracle,makeOwnKey,config,hooks.injectColumns,victimKey)"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "Capability boundary"
      ]
    ]
  },
  {
    "name": "Heldout constructed before attack",
    "changes": [
      {
        "file": "src/harness.ts",
        "before": "const choose=seeded(seed^0x45d9f3b);",
        "after": "const earlyHeldout=hooks.generator?hooks.generator(seed^0xa341316c):new HeldoutGenerator(seed^0xa341316c);const choose=seeded(seed^0x45d9f3b);"
      },
      {
        "file": "src/harness.ts",
        "before": "const heldout=hooks.generator?hooks.generator(seed^0xa341316c):new HeldoutGenerator(seed^0xa341316c),rows",
        "after": "const heldout=earlyHeldout,rows"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "Heldout stream"
      ]
    ]
  },
  {
    "name": "NoShift also removes MixColumns",
    "changes": [
      {
        "file": "src/aes/cipher.ts",
        "before": "noShift:{...REAL,shiftRows:false}",
        "after": "noShift:{...REAL,shiftRows:false,mixColumns:false}"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "Labelled ablation"
      ]
    ]
  },
  {
    "name": "Skipped realAES control and hardcoded zero",
    "changes": [
      {
        "file": "src/harness.ts",
        "before": "return {broken:await run(false),control:await run(true)}",
        "after": "return {broken:await run(false),control:{...await run(false),control:true,rows:[],successes:0}}"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noSub",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "WebCrypto reversed key",
    "changes": [
      {
        "file": "src/crosscheck.ts",
        "before": "importKey('raw',Uint8Array.from(key)",
        "after": "importKey('raw',Uint8Array.from(key).reverse()"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Browser WebCrypto uses the printed key",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "MDS omits 3x3 minors",
    "changes": [
      {
        "file": "src/aes/state.ts",
        "before": "for(let size=1;size<=4;size++)for",
        "after": "for(let size=1;size<=4;size++)if(size!==3)for"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "MDS all69"
      ]
    ]
  },
  {
    "name": "DDT includes zero difference",
    "changes": [
      {
        "file": "src/aes/sbox.ts",
        "before": "rows.slice(1).map",
        "after": "rows.slice(0).map"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Every field operation",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "Affine identity only diagonal",
    "changes": [
      {
        "file": "src/aes/sbox.ts",
        "before": "for(let y=0;y<256;y++)if",
        "after": "for(let y=x;y===x;y++)if"
      },
      {
        "file": "src/aes/sbox.ts",
        "before": "total:65536,affine:passed===65536",
        "after": "total:256,affine:passed===256"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "FIPS all256"
      ]
    ]
  },
  {
    "name": "Linear order stops at four",
    "changes": [
      {
        "file": "src/aes/state.ts",
        "before": "power<=8",
        "after": "power<=4"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "MDS all69"
      ]
    ]
  },
  {
    "name": "Byte lookup uses output index",
    "changes": [
      {
        "file": "src/attack/bytes.ts",
        "before": "const value=tables[input].get(ct[noMixPosition(input)])",
        "after": "const value=tables[input].get(ct[input])"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noMix",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "Singular ablation reported OK",
    "changes": [
      {
        "file": "src/harness.ts",
        "before": "kind:'implementation-error',message:'Singular L",
        "after": "kind:'control-fails',message:'Singular L"
      }
    ],
    "command": [
      "npx",
      [
        "vitest",
        "run",
        "-t",
        "Singular affine"
      ]
    ]
  },
  {
    "name": "Wrong mix mode uses inverse anyway",
    "changes": [
      {
        "file": "src/aes/cipher.ts",
        "before": "fault==='wrongMix'?mixColumns(state):invMixColumns(state)",
        "after": "fault==='wrongMix'?invMixColumns(state):invMixColumns(state)"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Inverse correct",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "Negative affine claim deleted",
    "changes": [
      {
        "file": "src/ui/act7.ts",
        "before": "A good-looking avalanche is not security. This affine-only AES \u2014 where every output byte depends on every input byte and about half the output bits flip per input-bit flip on average \u2014 is still broken by one known plaintext.",
        "after": "This affine-only map is broken."
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: affine",
        "--workers=1",
        "--retries=0"
      ]
    ]
  },
  {
    "name": "Avalanche counts only low seven bits",
    "changes": [
      {
        "file": "src/diagnostics.ts",
        "before": "n+weight(x)",
        "after": "n+weight(x&127)"
      }
    ],
    "command": [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: affine",
        "--workers=1",
        "--retries=0"
      ]
    ]
  }
];

for(const c of cases)if(c.command[1].includes('--grep')&&config)c.command[1].push('--config',config);
const files=[...new Set(cases.flatMap(c=>c.changes.map(x=>x.file)))];
if(spawnSync('git',['diff','--exit-code','--',...files],{encoding:'utf8'}).status!==0)throw Error('Commit source before mutation checks.');
pass(build,'baseline build');const baseline=hash(),evidence=[];mkdirSync('mutation-logs',{recursive:true});
for(const {name,changes,command}of cases){pass(command,name+': baseline test');const originals=new Map(changes.map(c=>[c.file,readFileSync(c.file,'utf8')]));let mutant;
try{for(const {file,before,after}of changes){const s=readFileSync(file,'utf8');if(s.split(before).length!==2)throw Error(name+': expected unique anchor '+before);writeFileSync(file,s.replace(before,after));}
const diff=spawnSync('git',['diff','--',...originals.keys()],{encoding:'utf8'}).stdout;if(!diff.trim())throw Error('Empty mutation');pass(build,name+': mutant build');mutant=hash();if(mutant===baseline)throw Error('Unchanged bundle');const r=run(command),output=r.stdout+r.stderr;writeFileSync('mutation-logs/'+name.replaceAll(' ','-')+'.log',output);if(r.status===0||!/expect\(|AssertionError|Error: expect/.test(output))throw Error(name+': no assertion kill\n'+output);
if(name==='AES256 extra SubWord omitted')pass(['npx',['vitest','run','-t','FIPS Appendix A1|FIPS 2001 Appendix C AES128']],name+': unaffected AES128 controls');evidence.push({name,unaffectedControls:name==='AES256 extra SubWord omitted'?['FIPS Appendix A1','FIPS 2001 Appendix C AES128']:undefined,sourceDiff:diff,baseline,mutant,owningTest:command[1][command[1].includes('--grep')?command[1].indexOf('--grep')+1:command[1].indexOf('-t')+1],failedTests:output.split('\n').filter(s=>/FAIL |✘|× /.test(s)),assertionFailure:true,retries:0});
}finally{for(const [file,s]of originals)writeFileSync(file,s);pass(build,name+': restore build');if(hash()!==baseline)throw Error('Restored artifact differs');pass(command,name+': restored test');}
evidence.at(-1).restoredGreen=true;writeFileSync('mutation-evidence.json',JSON.stringify(evidence,null,2)+'\n');console.log(name+': killed; exact artifact restored; owning test green');}

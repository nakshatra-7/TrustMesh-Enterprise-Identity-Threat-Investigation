import 'dotenv/config';
import { spawn,type ChildProcess } from 'node:child_process';
// Foreground supervisor: startup failures stop the group; does not kill unrelated processes.
const children:ChildProcess[]=[];let stopping=false;
function shutdown(){if(stopping)return;stopping=true;for(const child of children)child.kill('SIGTERM');}
process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
for(const args of [['--import','tsx','src/worker/main.ts'],['--import','tsx','src/worker/investigations.ts'],['node_modules/next/dist/bin/next','dev','--hostname','127.0.0.1']]){
  const child=spawn(process.execPath,args,{stdio:'inherit',env:process.env});children.push(child);child.on('error',()=>{process.exitCode=1;shutdown();});child.on('exit',code=>{if(!stopping){process.exitCode=code||1;shutdown();}});
}

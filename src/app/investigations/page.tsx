import { currentAnalyst } from '../../lib/auth';
import { redirect } from 'next/navigation';
import InvestigationConsole from './console';
export const dynamic='force-dynamic';
export default async function Investigations(){const analyst=await currentAnalyst();if(!analyst)redirect('/');return <InvestigationConsole analyst={analyst.username}/>;}

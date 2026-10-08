from pathlib import Path
import importlib.util,json,sys
root=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('reviewed_aee',root/'aee_verify.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
fixtures=Path(__file__).parent/'codex-fixtures'
failures=[];checks=0
def check(ok,label):
 global checks
 checks+=1
 if not ok:failures.append(label)
def finish():
 for label in failures:print('FAIL',label)
 print(str(checks)+' checks, '+str(len(failures))+' failures')
 sys.exit(1 if failures else 0)

key=bytes.fromhex(json.loads((fixtures/'public-keys.json').read_text())['substrateObservationKeys'][0]['publicKeyHex'])
for filename,kind in [('noncovering-referenced.json','moat-drop'),('noncovering-unreferenced.json','uncommitted-observation')]:
 for corrupt in [False,True]:
  s=json.loads((fixtures/filename).read_text())
  if corrupt:s['predicate']['observationRecords'][-1]['signatures'][0]['sig']=''
  v=a.Verifier(json.dumps(s).encode(),[key]);seen={};real=v.record_verifies
  def observe(record):
   outcome=real(record);seen[record.idx]=outcome;return outcome
  v.record_verifies=observe
  check(v.run(),kind+' structural validity unchanged')
  check(v.tiers==['attested','attested'],kind+' does not enter covering tier')
  index=len(s['predicate']['observationRecords'])-1
  check(index in seen and seen[index] is (not corrupt),kind+' signature is evaluated, corrupt='+str(corrupt))
finish()

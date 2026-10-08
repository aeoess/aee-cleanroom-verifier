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

for zone in ['Z','+00:00','-00:00']:
 for day in ['2026-06-23','2024-02-28']:
  check(a.parse_timestamp(day+'T23:59:60.125'+zone) is None,'reject midmonth '+day+zone)
for value in ['0000-01-01T00:00:00Z','1990-12-31T23:59:60Z','1990-12-31T23:59:60.9+00:00','1990-12-31T23:59:60-00:00']:
 check(a.parse_timestamp(value) is not None,'retain '+value)
check(a.parse_timestamp('1990-12-31T23:59:60.9Z') < a.parse_timestamp('1991-01-01T00:00:00Z'),'exact leap ordering')
s=json.loads((fixtures/'timestamp-artifact.json').read_text());s['predicate']['issuedAt']='2026-06-23T23:59:60Z'
check(not a.Verifier(json.dumps(s).encode()).run(),'reject issuedAt end to end')
check(not a.Verifier((fixtures/'midmonth-arming.json').read_bytes()).run(),'reject signed armedAt end to end')
finish()

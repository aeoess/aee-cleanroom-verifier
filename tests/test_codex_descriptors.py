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

base=json.loads((fixtures/'artifact.json').read_text())
def target(s,name):
 return s['subject'][0] if name=='subject' else s['predicate']['observationEnvironment'][name]
for name in ['subject','substrate','catchPolicy']:
 for field in ['name','uri','downloadLocation','mediaType','annotations','content']:
  s=json.loads(json.dumps(base));target(s,name)[field]=[] if field=='annotations' else 42
  v=a.Verifier(json.dumps(s).encode());check(not v.run(),name+' invalid '+field)
 for field in ['uri','downloadLocation']:
  for uri in ['HTTPS://example.com/path','https://EXAMPLE.com/path']:
   s=json.loads(json.dumps(base));target(s,name)[field]=uri
   v=a.Verifier(json.dumps(s).encode());check(not v.run(),name+' nonnormalized '+field+' '+uri)
 s=json.loads(json.dumps(base));target(s,name).update(name='test',uri='https://example.com/UPPER',downloadLocation='pkg:test/item',mediaType='text/plain',annotations={'arbitrary':[1,None]},content='AA==',unknown={'arbitrary':True})
 v=a.Verifier(json.dumps(s).encode());check(v.run() and v.result=='pass_indirect',name+' valid optional fields')
 s=json.loads(json.dumps(base));target(s,name)['content']='!!!'
 check(not a.Verifier(json.dumps(s).encode()).run(),name+' malformed base64 bytes')
for uri in ['relative/path','https://example.com/has space','https://example.com/%zz','https://[::g]/','https://example.com:bad/','https://example.com/path#one#two']:
 s=json.loads(json.dumps(base));s['subject'][0]['uri']=uri
 check(not a.Verifier(json.dumps(s).encode()).run(),'reject URI syntax '+uri)
for uri in ['urn:test:value','file:///tmp/a','https://[2001:db8::1]:443/a','https://[v1.test]/a','pkg:test/item@1','https://user:pass@example.com/path?x=%FF#part']:
 s=json.loads(json.dumps(base));s['subject'][0]['uri']=uri
 check(a.Verifier(json.dumps(s).encode()).run(),'retain URI syntax '+uri)
finish()

#!/usr/bin/env python3
"""Offline feasibility builds only. Does not enable downloaded-code execution."""
import importlib.util
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('agent_artifacts',ROOT/'scripts/agent_artifacts.py')
art=importlib.util.module_from_spec(spec);spec.loader.exec_module(art)
def main():
    catalog,_,_,fingerprint=art.inputs()
    art.main('prepare')
    tc=ROOT/'work/toolchains/mingw/usr/bin'
    cc=tc/'i686-w64-mingw32-gcc-posix'
    out=ROOT/'work/bin/collectors';out.mkdir(parents=True,exist_ok=True)
    results=[]
    for entry in catalog:
        file=out/(entry['id']+'.exe')
        command=[str(cc),'-std=c99','-O2','-s','-Wall','-Wextra','-ffunction-sections','-fdata-sections','-D__USE_MINGW_ANSI_STDIO=1','-D_WIN32_WINNT=0x0501','-DWINVER=0x0501','-DCOLLECTOR_ENTRY='+entry['entrypoint'],'-Icollectors/windows','-Iwork/bin','agent/windows/collector_main.c','collectors/windows/runtime.c',entry['source'],'-static','-static-libgcc','-Wl,--gc-sections,--no-insert-timestamp','-Wl,--major-subsystem-version,5,--minor-subsystem-version,1','-lws2_32','-liphlpapi','-ladvapi32','-o',str(file)]
        subprocess.run(command,cwd=ROOT,check=True)
        imports=subprocess.check_output([str(tc/'i686-w64-mingw32-objdump'),'-p',str(file)],text=True)
        if any(name in imports for name in ['_vsnprintf_s','BCryptGenRandom','GetTickCount64','InitializeCriticalSectionEx','CreateProcess','ShellExecute','WinExec']):raise ValueError('Forbidden standalone collector import')
        (out/(entry['id']+'-imports.txt')).write_text(imports)
        data=file.read_bytes();results.append({'id':entry['id'],'source':entry['source'],'entrypoint':entry['entrypoint'],'sha256':art.digest(data),'size':len(data)})
    m={'status':'experimental_offline_only_unsigned','source_fingerprint':fingerprint,'collectors':results,'network_job_executor':'still_builtin_collectors_not_these_files'}
    (out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps(m,indent=2))
if __name__=='__main__':main()

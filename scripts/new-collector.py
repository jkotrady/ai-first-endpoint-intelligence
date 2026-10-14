#!/usr/bin/env python3
"""Create an excluded native-collector draft; never activates or publishes code."""
import argparse
import json
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]

def create_draft(root,ident):
    if not re.fullmatch('F[0-9]{2}',ident):raise ValueError('Expected catalog ID F01-F50')
    planned=json.loads((root/'internal/console/collectors.json').read_text())
    item=next((c for c in planned if c['id']==ident),None)
    if item is None:raise ValueError('ID is outside approved 50-collector plan')
    if any(c['id']==ident for c in json.loads((root/'collectors/catalog.json').read_text())):
        raise ValueError('Already implemented; review/version existing collector instead')
    folder=root/'collectors/drafts'/ident
    folder.mkdir(parents=True,exist_ok=False)
    name=ident+'_collection.c'
    (folder/name).write_text('#include "collector.h"\n\n/* DRAFT. Implement read-only collection and explicit limits before review. */\nvoid collect_'+ident+'(void) {\n    error_result("collector_not_implemented", ERROR_CALL_NOT_IMPLEMENTED);\n}\n')
    fragment=dict(id=ident,name=item['description'],source='collectors/windows/'+name,entrypoint='collect_'+ident,limitations='DRAFT — define actual coverage and tested limits before promotion')
    (folder/'catalog-entry.json').write_text(json.dumps(fragment,ensure_ascii=False,indent=2)+'\n')
    (folder/'REVIEW.md').write_text('# '+ident+' — draft, excluded from every build\n\n'+item['description']+'\n\nOS: '+item['os_notes']+'\n\nRisk: '+item['risk_notes']+'\n\nBefore promotion record: API sources, exact fields, required rights, output/memory/time caps, Unicode, errors/partial results, XP/7 and modern OS evidence, independent source review. See docs/COLLECTOR-AUTHORING.md.\n')
    return folder

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('id');a=p.parse_args()
    try:folder=create_draft(ROOT,a.id)
    except (ValueError,FileExistsError) as e:raise SystemExit(str(e))
    print('Draft only:',folder.relative_to(ROOT))
if __name__=='__main__':main()

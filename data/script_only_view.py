# script-only 판정용 원문 보기. 담당자 터미널에만 출력한다. 에이전트 채팅에 붙이지 않는다(백신이 대화 기록을 잡음).
# 압축을 풀지 않고 메모리에서 읽는다. 아무것도 실행하지 않는다. 줄 번호를 붙여 보여 준다.
# 사용: cd data && python -I script_only_view.py <benchmark_id> [파일 이름 일부]
#   예: python -I script_only_view.py ASB04_000194            # SKILL.md + 코드 파일 전부
#       python -I script_only_view.py ASB04_000194 optimizer  # 이름에 'optimizer'가 든 파일만
import os
import sys
import tarfile

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I는 스크립트 폴더를 import 경로에서 빼므로 직접 넣는다
from script_only import is_code


def main():
    bid, part = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
    m = pd.read_csv("package_manifest.csv").set_index("benchmark_id").loc[bid]
    root = m.package_relative_path + "/"
    with tarfile.open(m.package_archive) as t:
        for mem in t:
            if not (mem.isfile() and mem.name.startswith(root)):
                continue
            rel, data = mem.name[len(root):], t.extractfile(mem).read()
            if not (os.path.basename(rel).lower() == "skill.md" or is_code(rel, data[:2])) or part not in rel:
                continue
            print(f"\n{'=' * 20} {rel} {'=' * 20}")
            for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                print(f"{i:5d}  {line}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()

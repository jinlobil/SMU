SMU Web 실행 방법
=================

1. ZIP 파일의 압축을 완전히 풉니다.
2. 최초 한 번 INSTALL_WEB.bat을 더블클릭합니다.
3. Node.js가 없다면 자동으로 Node.js LTS 설치를 시작합니다.
4. Node.js 설치가 끝나면 창을 닫고 INSTALL_WEB.bat을 다시 실행합니다.
5. 설치가 모두 끝난 다음부터는 START_WEB.bat만 더블클릭합니다.

설치 창에 "is not recognized as an internal or external command"가 여러 번
나왔다면, 한글이 들어간 이전 설치 파일의 Windows 인코딩 문제입니다.
새 ZIP을 다시 받은 뒤 영문 이름인 INSTALL_WEB.bat을 실행하세요.

설치 마지막에 framer-motion 또는 motion-dom의 "is not exported" 오류가
나왔다면 이전 웹 패키지 조합 문제입니다. 새 ZIP을 받은 뒤 INSTALL_WEB.bat을
다시 실행하면 해당 의존성을 사용하지 않는 새 화면으로 빌드됩니다.

브라우저 주소: http://127.0.0.1:8000

터미널 오류를 놓쳤다면 SHOW_WEB_LOG.bat을 더블클릭하세요.
전체 오류는 logs\web_server.log에 계속 저장됩니다. 서버 시작이 실패하면
START_WEB.bat이 이 로그를 메모장으로 자동으로 열고 창을 닫지 않습니다.

중요:
INSTALL_WEB.bat과 START_WEB.bat이 폴더에 보이지 않는다면 이전 버전 ZIP입니다.
이번 변경이 main 브랜치에 병합된 뒤 GitHub에서 새 ZIP을 다시 받으세요.

기존 설정과 데이터를 사용하려면 예전 SMU의 env, cache 폴더를 이 폴더로
복사하세요. env 폴더는 API 정보가 있으므로 GitHub에 업로드하지 마세요.

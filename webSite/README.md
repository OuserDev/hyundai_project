# 웹서버 설치 방법   
**apache2 웹 설치**   
ansible-playbook -i 프로젝트폴더/webSite/ansible_apache2/inventory.ini 프로젝트폴더/webSite/ansible_apache2/main.yml

**nginx 웹 설치**   
ansible-playbook -i 프로젝트폴더/webSite/ansible_nginx/inventory.ini 프로젝트폴더/webSite/ansible_nginx/main.yml

현재 경로가 opt/ansible_project/webSite/ansible_nginx일 경우
ansible-playbook -i inventory.ini main.yml

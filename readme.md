🛡️ AWS Integrated Security Audit Tool (v13)

SK쉴더스(SK Shieldus) 클라우드 보안 가이드라인(2024) 기반의 AWS 인프라 및 EKS 통합 보안 진단 자동화 도구입니다.

Automated AWS & EKS Security Audit Tool based on SK Shieldus Cloud Security Guidelines (2024).


🇰🇷 한국어 (Korean)

1. 프로젝트 소개 (Introduction)

이 프로젝트는 복잡한 클라우드 보안 점검을 단 한 번의 스크립트 실행으로 자동화하는 도구입니다.
IAM(계정), Network(방화벽), Data(암호화), EKS(컨테이너) 등 핵심 보안 영역을 전수 조사하여, 경영진 보고용 요약 리포트와 실무자용 상세 리포트를 자동으로 생성합니다.

🌟 핵심 특징 (Key Features)

Zero Impact (무중단): Read-Only API만 사용하여 운영 중인 서비스에 영향을 주지 않습니다.

No Cost (비용 절감): 유료 로깅 서비스(CloudWatch Logs Insights) 대신 무료 API를 사용하여 비용이 발생하지 않습니다.

Cross-Platform: Linux 및 macOS 환경을 모두 지원합니다.

Full Automation: 리전 내 모든 EKS 클러스터를 자동으로 식별하여 점검합니다.

2. 진단 범위 (Audit Scope)

SK쉴더스 가이드라인의 주요 통제 항목을 기준으로 진단합니다.

# 클라우드 보안 진단 항목 리스트

| 카테고리 (Category) | 코드 (Code) | 진단 내용 (Diagnostic Item) |
| :--- | :---: | :--- |
| **IAM** | 1.8 | 90일 이상 미사용 Access Key 식별 |
| | 1.9 | MFA(멀티팩터 인증) 미설정 계정 탐지 |
| **Network** | 3.1 | 위험 포트(SSH, RDP, DB) 전체 개방(0.0.0.0/0) 여부 |
| | 3.2 | 미사용 보안 그룹(Zombie SG) 식별 |
| | 3.3 | 네트워크 ACL(NACL) 커스텀 설정 여부 확인 |
| | 3.4 | 퍼블릭 서브넷(IGW 연결) 및 라우팅 테이블 점검 |
| **Data** | 4.1~3 | EBS, RDS, S3 데이터 암호화 설정 점검 |
| **Availability** | 3.7 | S3 퍼블릭 액세스 차단 설정 확인 |
| | 4.13 | RDS 자동 백업 활성화 여부 확인 |
| **EKS** | 1.11+ | 권한(RBAC), 파드 보안, 로깅 등 심층 진단 (Prowler 연동) |

3. 설치 및 실행 (Installation & Usage)

3.1 사전 요구 사항 (Prerequisites)
# 🛡️ AWS Integrated Security Audit Tool (v13)

SK쉴더스(SK Shieldus) 클라우드 보안 가이드라인(2024) 기반의 AWS 인프라 및 EKS 통합 보안 진단 자동화 도구입니다.

> Automated AWS & EKS Security Audit Tool based on SK Shieldus Cloud Security Guidelines (2024).

## 🇰🇷 한국어 (Korean)

### 1. 프로젝트 소개 (Introduction)
이 프로젝트는 복잡한 클라우드 보안 점검을 단 한 번의 스크립트 실행으로 자동화하는 도구입니다.
IAM(계정), Network(방화벽), Data(암호화), EKS(컨테이너) 등 핵심 보안 영역을 전수 조사하여, 경영진 보고용 요약 리포트와 실무자용 상세 리포트를 자동으로 생성합니다.

#### 🌟 핵심 특징 (Key Features)
* **Zero Impact (무중단):** Read-Only API만 사용하여 운영 중인 서비스에 영향을 주지 않습니다.
* **No Cost (비용 절감):** 유료 로깅 서비스(CloudWatch Logs Insights) 대신 무료 API를 사용하여 비용이 발생하지 않습니다.
* **Cross-Platform:** Linux 및 macOS 환경을 모두 지원합니다.
* **Full Automation:** 리전 내 모든 EKS 클러스터를 자동으로 식별하여 점검합니다.

### 2. 진단 범위 (Audit Scope)
SK쉴더스 가이드라인의 주요 통제 항목을 기준으로 진단합니다.

| 카테고리 (Category) | 코드 (Code) | 진단 내용 (Diagnostic Item) |
| :--- | :---: | :--- |
| **IAM** | 1.8 | 90일 이상 미사용 Access Key 식별 |
| | 1.9 | MFA(멀티팩터 인증) 미설정 계정 탐지 |
| **Network** | 3.1 | 위험 포트(SSH, RDP, DB) 전체 개방(0.0.0.0/0) 여부 |
| | 3.2 | 미사용 보안 그룹(Zombie SG) 식별 |
| | 3.3 | 네트워크 ACL(NACL) 커스텀 설정 여부 확인 |
| | 3.4 | 퍼블릭 서브넷(IGW 연결) 및 라우팅 테이블 점검 |
| **Data** | 4.1~3 | EBS, RDS, S3 데이터 암호화 설정 점검 |
| **Availability** | 3.7 | S3 퍼블릭 액세스 차단 설정 확인 |
| | 4.13 | RDS 자동 백업 활성화 여부 확인 |
| **EKS** | 1.11+ | 권한(RBAC), 파드 보안, 로깅 등 심층 진단 (Prowler 연동) |

### 3. 설치 및 실행 (Installation & Usage)

#### 3.1 사전 요구 사항 (Prerequisites)
이 스크립트는 아래 도구들을 사용합니다. 미리 설치해주세요.
* `aws-cli` (v2 권장)
* `jq` (JSON 파싱 도구)
* `prowler` (보안 진단 도구)
* `kubectl` (EKS 접속용)

**설치 명령어 예시 (Linux):**
```bash
sudo yum install jq -y
pip install prowler
이 스크립트는 아래 도구들을 사용합니다. 미리 설치해주세요.

aws-cli (v2 권장)

jq (JSON 파싱 도구)

prowler (보안 진단 도구)

kubectl (EKS 접속용)

설치 명령어 예시 (Linux):

sudo yum install jq -y
pip install prowler
```

3.2 실행 방법 (How to Run)

리포지토리 다운로드
```
git clone [https://github.com/YOUR_ID/YOUR_REPO.git](https://github.com/YOUR_ID/YOUR_REPO.git)
cd YOUR_REPO
```

AWS 인증 설정 (조회 권한 필요)
```
aws configure
```

스크립트 실행
```
chmod +x master_audit_v13.sh
./master_audit_v13.sh
```

4. 결과물 (Output)
```
실행이 완료되면 Total_Audit_Result_날짜 폴더가 생성됩니다.

0_FINAL_EXECUTIVE_REPORT.md: [핵심] 경영진 보고용 요약 리포트

1_IAM_Compliance.md: 계정 보안 상세 결과

2_Network_Security.md: 네트워크 보안 상세 결과

3_Data_Protection.md: 데이터 암호화 상세 결과 (S3 정책 포함)

5_EKS_Audit_All/: EKS 클러스터별 상세 진단 결과 폴더
```

🇺🇸 English

1. Introduction

This tool automates the security audit process for AWS environments based on the SK Shieldus Cloud Security Guideline (2024).
It performs a comprehensive scan across IAM, Network, Data, and EKS resources and generates an intuitive Markdown report.

🌟 Key Features

Zero Impact: Uses 100% Read-Only APIs to ensure no disruption to live services.

No Cost: Eliminates expensive scanning costs by utilizing free tier APIs and open-source tools.

Cross-Platform: Supports both Linux and macOS.

Full Automation: Automatically detects and scans all active EKS clusters in the region.

2. Audit Scope

| Category | Code | Description |
| :--- | :---: | :--- |
| **IAM** | 1.8 | Detect Access Keys unused for >90 days |
| | 1.9 | Identify users without MFA |
| **Network** | 3.1 | Check for risky ports (SSH, RDP, DB) open to 0.0.0.0/0 |
| | 3.2 | Identify unused Security Groups |
| | 3.3 | Check Network ACL configurations |
| | 3.4 | Audit Routing Tables & Public Subnets |
| **Data** | 4.1~3 | Check Encryption for EBS, RDS, S3 |
| **Availability** | 3.7 | Check S3 Public Access Block settings |
| | 4.13 | Verify RDS Automated Backups |
| **EKS** | 1.11+ | Deep dive into RBAC, Pod Security, Logging (via Prowler) |

3. Installation & Usage

3.1 Prerequisites

Ensure the following tools are installed: aws-cli, jq, prowler, kubectl.

Installation Example (Linux):
```
sudo yum install jq -y
pip install prowler
```

3.2 How to Run

Clone Repository
```
git clone [https://github.com/YOUR_ID/YOUR_REPO.git](https://github.com/YOUR_ID/YOUR_REPO.git)
cd YOUR_REPO
```

Configure AWS Credentials
```
aws configure
```

Run Script
```
chmod +x master_audit_v13.sh
./master_audit_v13.sh
```

4. Output Structure
```
A timestamped folder Total_Audit_Result_YYYYMMDD will be created.

0_FINAL_EXECUTIVE_REPORT.md: Executive Summary Report

1_IAM_Compliance.md: IAM Details

2_Network_Security.md: Network Details

3_Data_Protection.md: Data Encryption Details

5_EKS_Audit_All/: Detailed EKS Reports per Cluster
```
⚠️ Disclaimer

This tool is for auditing purposes only. It does not modify any resources. Always review the findings manually before taking remediation actions.

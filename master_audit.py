#!/usr/bin/env python3
# ==============================================================================
# AWS 통합 보안 진단 도구 — Python(boto3) 포트 (SKELETON)
#
# 목적:
#   master_audit_v13.sh 의 Python 이식 버전. jq/bash 의존성 없이 동작하도록
#   boto3 만으로 재작성하는 것을 목표로 합니다.
#
# 현재 상태:
#   - [DONE] Phase 1. IAM (Access Key 수명 / MFA) — 실제 동작
#   - [TODO] Phase 2. Network (SG / NACL / RT)
#   - [TODO] Phase 3. Data (EBS / RDS / S3)
#   - [TODO] Phase 4. Availability (S3 Public Access / RDS Backup)
#   - [TODO] Phase 5. EKS (Prowler 연동)
#   각 TODO 는 아래 bash 원본의 동일 Phase 로직을 boto3 로 옮기면 됩니다.
#
# 실행:
#   pip install boto3
#   aws configure          # 조회(Read-Only) 권한 필요
#   python3 master_audit.py
# ==============================================================================

from __future__ import annotations

import os
from datetime import datetime, timezone

import boto3

# --- [CONFIGURATION] ---------------------------------------------------------
REGION = "ap-northeast-2"
CHECK_PORTS = [22, 3389, 3306, 5432, 27017]
IAM_KEY_MAX_DAYS = 90
# -----------------------------------------------------------------------------

DATE_STR = datetime.now().strftime("%Y%m%d_%H%M")
BASE_DIR = f"./Total_Audit_Result_{DATE_STR}"


def log(msg: str) -> None:
    print(f"\033[1;32m[INFO]\033[0m {msg}")


def write_report(filename: str, content: str) -> None:
    path = os.path.join(BASE_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ==============================================================================
# Phase 1. IAM  — [DONE]
# ==============================================================================
def audit_iam() -> str:
    log("Step 1. IAM 점검 중...")
    iam = boto3.client("iam")

    lines = [
        "# 1. IAM 규정 준수",
        f"## 1.1 [1.8] Access Key 수명 ({IAM_KEY_MAX_DAYS}일)",
        "| 사용자 | Key ID | 경과일 | 상태 | 권고 |",
        "|---|---|---|---|---|",
    ]

    now = datetime.now(timezone.utc)
    users = [u["UserName"] for u in iam.list_users().get("Users", [])]

    for user in users:
        keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
        for key in keys:
            age_days = (now - key["CreateDate"]).days
            if age_days > IAM_KEY_MAX_DAYS and key["Status"] == "Active":
                lines.append(
                    f"| `{user}` | `{key['AccessKeyId']}` | **{age_days}일** | 🔴 Active | 교체 |"
                )

    lines += [
        "",
        "## 1.2 [1.9] MFA 미설정",
        "| 사용자 | 상태 | 권고 |",
        "|---|---|---|",
    ]

    for user in users:
        mfa = iam.list_mfa_devices(UserName=user).get("MFADevices", [])
        try:
            iam.get_login_profile(UserName=user)  # 콘솔 로그인 가능 사용자만 대상
            has_login = True
        except iam.exceptions.NoSuchEntityException:
            has_login = False
        if has_login and not mfa:
            lines.append(f"| `{user}` | ❌ 미설정 | 설정 필수 |")

    report = "\n".join(lines) + "\n"
    write_report("1_IAM_Compliance.md", report)
    return report


# ==============================================================================
# Phase 2. Network  — [TODO]
# ==============================================================================
def audit_network() -> None:
    """SG 위험 포트 개방 / 미사용 SG / NACL / 라우팅 테이블 점검.

    참고: master_audit_v13.sh 의 Phase 2 (describe-security-groups,
    describe-network-interfaces, describe-network-acls, describe-route-tables)
    를 boto3 ec2 client 로 이식하면 됩니다.
    """
    log("Step 2. 네트워크 점검 — [TODO] 미구현")


# ==============================================================================
# Phase 3. Data Protection  — [TODO]
# ==============================================================================
def audit_data() -> None:
    """EBS / RDS / S3 암호화 및 S3 버킷 정책 덤프.

    참고: bash Phase 3 (describe-volumes, describe-db-instances,
    list-buckets + get-bucket-encryption + get-bucket-policy) 이식.
    """
    log("Step 3. 데이터 보호 점검 — [TODO] 미구현")


# ==============================================================================
# Phase 4. Availability  — [TODO]
# ==============================================================================
def audit_availability() -> None:
    """S3 퍼블릭 액세스 차단 / RDS 자동 백업 점검.

    참고: bash Phase 4 (get-public-access-block, BackupRetentionPeriod) 이식.
    """
    log("Step 4. 가용성 점검 — [TODO] 미구현")


# ==============================================================================
# Phase 5. EKS  — [TODO]
# ==============================================================================
def audit_eks() -> None:
    """EKS 클러스터 Prowler 연동 진단.

    참고: bash Phase 5 (eks list-clusters + prowler aws/kubernetes) 이식.
    subprocess 로 prowler 를 호출하는 방식이 가장 단순합니다.
    """
    log("Step 5. EKS 점검 — [TODO] 미구현")


def main() -> None:
    os.makedirs(os.path.join(BASE_DIR, "evidence_s3_policies"), exist_ok=True)
    print("========================================================")
    print(" 🛡️  AWS 통합 보안 진단 시작 (Python skeleton)")
    print("========================================================")

    audit_iam()
    audit_network()
    audit_data()
    audit_availability()
    audit_eks()

    log(f"✅ 완료! 결과 폴더: {BASE_DIR}")


if __name__ == "__main__":
    main()

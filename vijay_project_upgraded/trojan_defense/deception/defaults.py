"""Default synthetic decoy blueprints for Cyber Deception Engine.

All content is strictly synthetic, non-operational, and explicitly labeled as canary data.
Never contains real credentials, system secrets, or executable payloads.
"""

from trojan_defense.deception.models import DecoyDefinition, DecoyType


def get_default_decoy_definitions() -> list[DecoyDefinition]:
    """Return default set of harmless synthetic decoy file and directory definitions."""
    return [
        # 1. Directory Decoys
        DecoyDefinition(
            decoy_id="decoy_dir_documents",
            artifact_type=DecoyType.DIRECTORY,
            relative_path="documents",
            purpose="synthetic_documents_container",
        ),
        DecoyDefinition(
            decoy_id="decoy_dir_config",
            artifact_type=DecoyType.DIRECTORY,
            relative_path="config",
            purpose="synthetic_configuration_container",
        ),
        DecoyDefinition(
            decoy_id="decoy_dir_credentials",
            artifact_type=DecoyType.DIRECTORY,
            relative_path="credentials",
            purpose="synthetic_credentials_container",
        ),
        DecoyDefinition(
            decoy_id="decoy_dir_backup",
            artifact_type=DecoyType.DIRECTORY,
            relative_path="backup",
            purpose="synthetic_backup_container",
        ),

        # 2. File Decoys
        DecoyDefinition(
            decoy_id="decoy_file_notes",
            artifact_type=DecoyType.FILE,
            relative_path="documents/project_notes.txt",
            content=(
                "# INTERNAL RESEARCH CANARY DOCUMENT\n"
                "Project: Cross-Platform Trojan Defense Evaluation\n"
                "Environment: Synthetic Deception Sandbox\n"
                "Notice: This is a synthetic decoy artifact. Contains no operational data.\n"
                "Synthetic-Tag: CANARY_RESEARCH_DOC_001\n"
            ),
            purpose="canary_project_notes",
        ),
        DecoyDefinition(
            decoy_id="decoy_file_app_ini",
            artifact_type=DecoyType.FILE,
            relative_path="config/application.ini",
            content=(
                "[application]\n"
                "app_name=EnterpriseInternalPortal\n"
                "environment=synthetic_demo\n"
                "debug=false\n\n"
                "[database]\n"
                "host=synthetic-db.internal.local\n"
                "port=5432\n"
                "username=SYNTHETIC_DB_USER\n"
                "password=DEMO_PASSWORD_NOT_REAL\n"
            ),
            purpose="canary_application_config",
        ),
        DecoyDefinition(
            decoy_id="decoy_file_cloud_tokens",
            artifact_type=DecoyType.FILE,
            relative_path="credentials/cloud_tokens.txt",
            content=(
                "[default]\n"
                "aws_access_key_id=SYNTHETIC_CANARY_AKIA_NOT_REAL_001\n"
                "aws_secret_access_key=SYNTHETIC_SECRET_NOT_REAL_DEMO_CANARY\n"
                "region=us-east-1\n"
            ),
            purpose="canary_cloud_credentials",
        ),
        DecoyDefinition(
            decoy_id="decoy_file_backup_csv",
            artifact_type=DecoyType.FILE,
            relative_path="backup/inventory_manifest.csv",
            content=(
                "AssetID,Hostname,Role,BackupStatus\n"
                "SRV-001,dc01.synthetic.local,DomainController,Verified\n"
                "SRV-002,db01.synthetic.local,DatabaseCluster,Verified\n"
                "SRV-003,app01.synthetic.local,ApplicationNode,Pending\n"
            ),
            purpose="canary_backup_manifest",
        ),
    ]

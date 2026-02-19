"""Create jobs table

Revision ID: 001
Revises: 
Create Date: 2026-02-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("request_client_id", sa.String(128), nullable=False),
        sa.Column("client_name", sa.String(256), nullable=True),
        sa.Column("job_state", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("tombstoned", sa.Boolean, nullable=False, server_default="false"),
        sa.CheckConstraint(
            "job_state IN ('CREATED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_job_state",
        ),
    )

    op.create_index("ix_jobs_client_id", "jobs", ["client_id"])
    op.create_index("ix_jobs_job_state", "jobs", ["job_state"])
    op.create_index("ix_jobs_created_at", "jobs", ["created_at"])
    op.create_index("ix_jobs_client_created", "jobs", ["client_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_jobs_client_created", table_name="jobs")
    op.drop_index("ix_jobs_created_at", table_name="jobs")
    op.drop_index("ix_jobs_job_state", table_name="jobs")
    op.drop_index("ix_jobs_client_id", table_name="jobs")
    op.drop_table("jobs")

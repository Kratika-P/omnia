"""Create job_stages table

Revision ID: 002
Revises: 001
Create Date: 2026-01-26

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "job_stages",
        sa.Column(
            "job_id",
            sa.String(36),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("stage_name", sa.String(30), primary_key=True, nullable=False),
        sa.Column("stage_state", sa.String(20), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(50), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.CheckConstraint(
            "stage_state IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED')",
            name="ck_stages_stage_state",
        ),
    )

    op.create_index("ix_stages_stage_state", "job_stages", ["stage_state"])
    op.create_index("ix_stages_job_state", "job_stages", ["job_id", "stage_state"])


def downgrade() -> None:
    op.drop_index("ix_stages_job_state", table_name="job_stages")
    op.drop_index("ix_stages_stage_state", table_name="job_stages")
    op.drop_table("job_stages")

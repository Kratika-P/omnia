"""Create idempotency_keys table

Revision ID: 003
Revises: 002
Create Date: 2026-01-26

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "idempotency_keys",
        sa.Column("idempotency_key", sa.String(255), primary_key=True, nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_idempotency_job_id", "idempotency_keys", ["job_id"])
    op.create_index("ix_idempotency_client_id", "idempotency_keys", ["client_id"])
    op.create_index("ix_idempotency_created_at", "idempotency_keys", ["created_at"])
    op.create_index("ix_idempotency_expires", "idempotency_keys", ["expires_at"])
    op.create_index(
        "ix_idempotency_client_created",
        "idempotency_keys",
        ["client_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_idempotency_client_created", table_name="idempotency_keys")
    op.drop_index("ix_idempotency_expires", table_name="idempotency_keys")
    op.drop_index("ix_idempotency_created_at", table_name="idempotency_keys")
    op.drop_index("ix_idempotency_client_id", table_name="idempotency_keys")
    op.drop_index("ix_idempotency_job_id", table_name="idempotency_keys")
    op.drop_table("idempotency_keys")

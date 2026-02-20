"""Create artifact_metadata table

Revision ID: 20260219_005
Revises: 20260219_004
Create Date: 2026-02-19 13:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '20260219_005'
down_revision: Union[str, None] = '20260219_004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create artifact_metadata table
    op.create_table(
        'artifact_metadata',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('stage_name', sa.String(length=50), nullable=False),
        sa.Column('label', sa.String(length=100), nullable=False),
        sa.Column('artifact_ref', sa.JSON(), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('content_type', sa.String(length=100), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['job_id'], ['jobs.id'], ondelete='CASCADE'),
    )
    
    # Create indexes for performance
    op.create_index('idx_artifact_metadata_job_id', 'artifact_metadata', ['job_id'])
    op.create_index('idx_artifact_metadata_job_label', 'artifact_metadata', ['job_id', 'label'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('idx_artifact_metadata_job_label', table_name='artifact_metadata')
    op.drop_index('idx_artifact_metadata_job_id', table_name='artifact_metadata')
    
    # Drop table
    op.drop_table('artifact_metadata')

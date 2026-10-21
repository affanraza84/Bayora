"""add_audit_checkpoints

Revision ID: 0002_add_audit_checkpoints
Revises: 40d708ae532a
Create Date: 2026-10-21 21:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002_add_audit_checkpoints'
down_revision: Union[str, Sequence[str], None] = '40d708ae532a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_checkpoints',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('start_sequence', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=False),
        sa.Column('end_sequence', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=False),
        sa.Column('root_hash', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('signer_key_id', sa.String(length=100), nullable=False),
        sa.Column('ed25519_signature', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_checkpoints_tenant_seq', 'audit_checkpoints', ['tenant_id', 'start_sequence', 'end_sequence'], unique=False)
    op.create_index(op.f('ix_audit_checkpoints_tenant_id'), 'audit_checkpoints', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_checkpoints_tenant_id'), table_name='audit_checkpoints')
    op.drop_index('idx_checkpoints_tenant_seq', table_name='audit_checkpoints')
    op.drop_table('audit_checkpoints')

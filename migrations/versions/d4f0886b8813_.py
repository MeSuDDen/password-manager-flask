"""empty message

Revision ID: d4f0886b8813
Revises: 785f9e024023
Create Date: 2024-04-10 23:56:30.531994

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4f0886b8813'
down_revision = '785f9e024023'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reset_token', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('reset_token_expiration', sa.DateTime(), nullable=True))
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=60),
               type_=sa.String(length=120),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('password',
               existing_type=sa.String(length=120),
               type_=sa.VARCHAR(length=60),
               existing_nullable=False)
        batch_op.drop_column('reset_token_expiration')
        batch_op.drop_column('reset_token')

    # ### end Alembic commands ###

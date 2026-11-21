use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "secret_versions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub secret_id: String,
    pub version: i64,
    pub project_id: Option<String>,
    pub key_cipher: Option<String>,
    pub value_cipher: Option<String>,
    pub note_cipher: Option<String>,
    pub key_plain: Option<String>,
    pub value_plain: Option<String>,
    pub note_plain: Option<String>,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub valid_from: i64,
    pub replaced_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::secret::Entity",
        from = "Column::SecretId",
        to = "super::secret::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Secret,
}

impl Related<super::secret::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Secret.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

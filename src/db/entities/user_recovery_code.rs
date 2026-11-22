use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "user_recovery_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: String,
    pub code_digest: String,
    pub used_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

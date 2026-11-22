use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "user_passkeys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: String,
    /// Base64url of the credential ID the authenticator chose.
    pub credential_id: String,
    /// Base64url of the COSE public key. Not a secret.
    pub public_key: String,
    pub sign_count: i64,
    /// JSON array of transport hints reported at registration.
    pub transports: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

use actixutils::viewset::*;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::sync::Arc;
use uuid::Uuid;


#[derive(Entity, FromRow, Serialize)]
#[entity(
    table = "users",
    create = "CreateUser",
    update = "UpdateUser",
    response = "UserDto"
)]
pub struct User {
    #[entity(pk)]
    id: Uuid,
    #[entity(searchable, sortable, filterable)]
    username: String,
    #[entity(sortable, filterable)]
    email: String,
    #[entity(sortable)]
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateUser {
    name: String,
    email: Decimal,
}

// `skip_serializing_if` is what makes PATCH semantics work: an omitted
// field in the request body stays absent from the serialized JSON, so the
// default `update_columns` (see Repository) never touches that column.
// Without it, `None` would serialize to `null` and the field would be
// wiped on every PATCH.
#[derive(Serialize, Deserialize)]
pub struct UpdateUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

#[derive(Serialize)]
pub struct UserDto {
    id: Uuid,
    username: String,
    email: String,
}

impl From<User> for UserDto {
    fn from(p: User) -> Self {
        Self {
            id: p.id,
            username: p.username,
            email: p.email,
        }
    }
}


pub struct UserRepository;

impl Repository for UserRepository {
    type Entity = User;
}

pub struct UserService {
    repo: UserRepository,
}

#[async_trait::async_trait]
impl Service for UserService {
    type Repository = UserRepository;
    type User = (); // no auth wiring in this minimal example

    fn repository(&self) -> &Self::Repository {
        &self.repo
    }

    // Only override the one hook we actually need.
    async fn before_create(
        &self,
        _ctx: &RequestContext<()>,
        _dto: CreateUser,
    ) -> Result<CreateUser, ApiError> {
        return Err(ApiError::Validation("manual create not allowed, use registration endpoint".into()));
    }
}


pub struct UserViewSet {
    service: UserService,
}

impl ViewSet for UserViewSet {
    type Service = UserService;

    fn service(&self) -> &Self::Service {
        &self.service
    }
}

pub fn create_viewset()->Arc<UserViewSet>{
    let repo = UserRepository{};
    let service = UserService{repo};
   Arc::new (UserViewSet{service})
}

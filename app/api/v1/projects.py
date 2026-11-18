from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Response, status
from fastapi.responses import JSONResponse

from app.api.deps import CtxDep, ProjectServiceDep, require_permission, writable_claims
from app.core.security import AccessClaims
from app.schemas import Page, ProjectCreate, ProjectOut, ProjectUpdate, problem_responses

router = APIRouter(prefix="/v1/projects", tags=["projects"])

ReadClaims = Annotated[AccessClaims, Depends(require_permission("project:read"))]
WriteClaims = Annotated[AccessClaims, Depends(require_permission("project:write"))]
ERRORS = problem_responses(401, 403, 404)
IdempotencyKeyHeader = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9_\-:.]+$",
        description=(
            "Replaying the same key within 24 h returns the first response and creates one row"
        ),
    ),
]


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=ProjectOut,
    responses={**ERRORS, **problem_responses(409, 422)},
    dependencies=[Depends(writable_claims)],
    summary="Create a project (honours Idempotency-Key)",
)
async def create_project(
    body: ProjectCreate,
    claims: WriteClaims,
    svc: ProjectServiceDep,
    idempotency_key: IdempotencyKeyHeader = None,
) -> JSONResponse:
    status_code, payload, replayed = await svc.create(claims.sub, body, idempotency_key)
    headers = {"Location": f"/v1/projects/{payload['id']}"}
    if idempotency_key is not None:
        headers["Idempotent-Replayed"] = "true" if replayed else "false"
    return JSONResponse(payload, status_code=status_code, headers=headers)


@router.get(
    "",
    response_model=Page[ProjectOut],
    responses=ERRORS,
    summary="List own projects (cursor pagination)",
)
async def list_projects(
    claims: ReadClaims,
    svc: ProjectServiceDep,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Page[ProjectOut]:
    rows, next_cursor = await svc.list_own(claims.sub, cursor, limit)
    return Page[ProjectOut](
        items=[ProjectOut.model_validate(r) for r in rows], next_cursor=next_cursor
    )


@router.get(
    "/{project_id}",
    response_model=ProjectOut,
    responses=ERRORS,
    summary="Read one project (owner or admin)",
)
async def get_project(
    project_id: uuid.UUID, claims: ReadClaims, svc: ProjectServiceDep
) -> ProjectOut:
    return ProjectOut.model_validate(await svc.get(project_id, claims.sub))


@router.patch(
    "/{project_id}",
    response_model=ProjectOut,
    responses=ERRORS,
    dependencies=[Depends(writable_claims)],
    summary="Update a project (owner or admin)",
)
async def update_project(
    project_id: uuid.UUID, body: ProjectUpdate, claims: WriteClaims, svc: ProjectServiceDep
) -> ProjectOut:
    return ProjectOut.model_validate(await svc.update(project_id, claims.sub, body))


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=ERRORS,
    dependencies=[Depends(writable_claims)],
    summary="Soft-delete a project (owner or admin)",
)
async def delete_project(
    project_id: uuid.UUID, claims: WriteClaims, svc: ProjectServiceDep, ctx: CtxDep
) -> Response:
    await svc.delete(project_id, claims.sub, ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

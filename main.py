import hmac
import os
import time
from collections import defaultdict, deque
from datetime import date
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import Job, ListingReport, ServiceProvider, WorkerProfile
from .schemas import (
    JobCreate,
    JobRead,
    ReportCreate,
    ServiceCreate,
    ServiceRead,
    WorkerAdminRead,
    WorkerCreate,
    WorkerRead,
)


Base.metadata.create_all(bind=engine)
app = FastAPI(title="ManaLocal API", version="1.0.0")
origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["X-Total-Count", "X-Page", "X-Page-Size"],
)

_submissions: dict[str, deque[float]] = defaultdict(deque)
RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 3600


def enforce_submission_limit(request: Request) -> None:
    now = time.monotonic()
    events = _submissions[request.client.host if request.client else "unknown"]
    while events and now - events[0] > RATE_WINDOW_SECONDS:
        events.popleft()
    if len(events) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many submissions. Please try again later.")
    events.append(now)


def require_admin(authorization: Annotated[str | None, Header()] = None) -> None:
    secret = os.getenv("ADMIN_SECRET", "")
    if len(secret) < 24:
        raise HTTPException(status_code=503, detail="Admin moderation is not configured.")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied, secret):
        raise HTTPException(status_code=401, detail="Valid admin credentials are required.")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/jobs", response_model=list[JobRead])
def list_jobs(
    response: Response,
    q: str | None = None,
    category: str | None = None,
    location: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    statement = select(Job).where(Job.status == "approved", Job.expires_at >= date.today())
    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(or_(Job.title.ilike(term), Job.description.ilike(term), Job.employer_name.ilike(term)))
    if category:
        statement = statement.where(Job.category.ilike(f"%{category.strip()}%"))
    if location:
        statement = statement.where(Job.location.ilike(f"%{location.strip()}%"))
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(statement.subquery())) or 0)
    response.headers["X-Page"] = str(page)
    response.headers["X-Page-Size"] = str(page_size)
    return db.scalars(statement.order_by(Job.posted_at.desc(), Job.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()


@app.get("/api/jobs/{listing_id}", response_model=JobRead)
def get_job(listing_id: int, db: Session = Depends(get_db)):
    job = db.get(Job, listing_id)
    if not job or job.status != "approved" or job.expires_at < date.today():
        raise HTTPException(status_code=404, detail="Listing not found.")
    return job


@app.post("/api/jobs", response_model=JobRead, status_code=201)
def submit_job(payload: JobCreate, request: Request, db: Session = Depends(get_db)):
    enforce_submission_limit(request)
    job = Job(**payload.model_dump(), status="pending")
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@app.get("/api/services", response_model=list[ServiceRead])
def list_services(
    response: Response,
    q: str | None = None,
    category: str | None = None,
    location: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    statement = select(ServiceProvider).where(ServiceProvider.status == "approved")
    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(or_(ServiceProvider.service_name.ilike(term), ServiceProvider.description.ilike(term), ServiceProvider.provider_name.ilike(term)))
    if category:
        statement = statement.where(ServiceProvider.category.ilike(f"%{category.strip()}%"))
    if location:
        statement = statement.where(ServiceProvider.service_area.ilike(f"%{location.strip()}%"))
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(statement.subquery())) or 0)
    response.headers["X-Page"] = str(page)
    response.headers["X-Page-Size"] = str(page_size)
    return db.scalars(statement.order_by(ServiceProvider.submitted_at.desc(), ServiceProvider.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()


@app.get("/api/services/{listing_id}", response_model=ServiceRead)
def get_service(listing_id: int, db: Session = Depends(get_db)):
    service = db.get(ServiceProvider, listing_id)
    if not service or service.status != "approved":
        raise HTTPException(status_code=404, detail="Listing not found.")
    return service


@app.post("/api/services", response_model=ServiceRead, status_code=201)
def submit_service(payload: ServiceCreate, request: Request, db: Session = Depends(get_db)):
    enforce_submission_limit(request)
    service = ServiceProvider(**payload.model_dump(), status="pending")
    db.add(service)
    db.commit()
    db.refresh(service)
    return service


def public_worker(profile: WorkerProfile) -> WorkerRead:
    result = WorkerRead.model_validate(profile)
    if not profile.contact_consent:
        result = result.model_copy(update={"contact_number": None, "whatsapp_preferred": False})
    return result


@app.get("/api/workers", response_model=list[WorkerRead])
def list_workers(
    response: Response,
    q: str | None = None,
    category: str | None = None,
    village: str | None = None,
    mandal: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    statement = select(WorkerProfile).where(WorkerProfile.status == "approved")
    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(or_(
            WorkerProfile.display_name.ilike(term),
            WorkerProfile.service_category.ilike(term),
            WorkerProfile.village.ilike(term),
            WorkerProfile.mandal.ilike(term),
            WorkerProfile.nearby_areas.ilike(term),
            WorkerProfile.description.ilike(term),
        ))
    if category:
        statement = statement.where(WorkerProfile.service_category == category.strip().lower())
    if village:
        statement = statement.where(WorkerProfile.village.ilike(f"%{village.strip()}%"))
    if mandal:
        statement = statement.where(WorkerProfile.mandal.ilike(f"%{mandal.strip()}%"))
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(statement.subquery())) or 0)
    response.headers["X-Page"] = str(page)
    response.headers["X-Page-Size"] = str(page_size)
    profiles = db.scalars(
        statement.order_by(WorkerProfile.submitted_at.desc(), WorkerProfile.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return [public_worker(profile) for profile in profiles]


@app.get("/api/workers/{listing_id}", response_model=WorkerRead)
def get_worker(listing_id: int, db: Session = Depends(get_db)):
    profile = db.get(WorkerProfile, listing_id)
    if not profile or profile.status != "approved":
        raise HTTPException(status_code=404, detail="Listing not found.")
    return public_worker(profile)


@app.post("/api/workers", response_model=WorkerRead, status_code=201)
def submit_worker(payload: WorkerCreate, request: Request, db: Session = Depends(get_db)):
    enforce_submission_limit(request)
    duplicate = db.scalar(select(WorkerProfile.id).where(
        WorkerProfile.contact_number == payload.contact_number,
        WorkerProfile.service_category == payload.service_category,
        func.lower(WorkerProfile.village) == payload.village.strip().lower(),
        func.lower(WorkerProfile.mandal) == payload.mandal.strip().lower(),
        WorkerProfile.status.in_(("pending", "approved")),
    ))
    if duplicate:
        raise HTTPException(status_code=409, detail="A worker profile for this category and village is already submitted.")
    profile = WorkerProfile(**payload.model_dump(), status="pending")
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return public_worker(profile)


@app.post("/api/reports", status_code=201)
def submit_report(payload: ReportCreate, request: Request, db: Session = Depends(get_db)):
    enforce_submission_limit(request)
    models = {"job": Job, "service": ServiceProvider, "worker": WorkerProfile}
    model = models[payload.listing_type]
    if not db.get(model, payload.listing_id):
        raise HTTPException(status_code=404, detail="Listing not found.")
    report = ListingReport(**payload.model_dump())
    db.add(report)
    db.commit()
    return {"message": "Report received. Thank you for helping keep ManaLocal safe."}


@app.get("/api/admin/pending")
def pending_listings(
    _: None = Depends(require_admin),
    db: Session = Depends(get_db),
):
    jobs = db.scalars(select(Job).where(Job.status == "pending").order_by(Job.id)).all()
    services = db.scalars(select(ServiceProvider).where(ServiceProvider.status == "pending").order_by(ServiceProvider.id)).all()
    reports = db.scalars(select(ListingReport).where(ListingReport.status == "pending").order_by(ListingReport.id)).all()
    return {
        "jobs": [JobRead.model_validate(row) for row in jobs],
        "services": [ServiceRead.model_validate(row) for row in services],
        "workers": [WorkerAdminRead.model_validate(row) for row in db.scalars(
            select(WorkerProfile).where(WorkerProfile.status == "pending").order_by(WorkerProfile.id)
        ).all()],
        "reports": [{"id": row.id, "listing_type": row.listing_type, "listing_id": row.listing_id, "reason": row.reason, "details": row.details} for row in reports],
    }


@app.patch("/api/admin/reports/{report_id}/review", dependencies=[Depends(require_admin)])
def review_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(ListingReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    report.status = "reviewed"
    db.commit()
    return {"id": report_id, "status": report.status}


@app.patch("/api/admin/{listing_type}/{listing_id}/{action}", dependencies=[Depends(require_admin)])
def moderate_listing(
    listing_type: str,
    listing_id: int,
    action: str,
    db: Session = Depends(get_db),
):
    models = {"job": Job, "service": ServiceProvider, "worker": WorkerProfile}
    statuses = {"approve": "approved", "reject": "rejected", "expire": "expired"}
    if listing_type not in models or action not in statuses:
        raise HTTPException(status_code=404, detail="Moderation action not found.")
    listing = db.get(models[listing_type], listing_id)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found.")
    listing.status = statuses[action]
    db.commit()
    return {"id": listing_id, "status": listing.status}

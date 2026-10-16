from app.database.database import Base, engine
from app.models.scan import Scan
from app.models.finding_record import FindingRecord

Base.metadata.create_all(bind=engine)

print("Database tables created successfully!")
print("Tables:", Base.metadata.tables.keys())
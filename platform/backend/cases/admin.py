from django.contrib import admin

from .models import (
    AuditLog,
    CollectionRun,
    CustodyEvent,
    Finding,
    Host,
    IOC,
    Investigation,
    MemoryAnalysisRun,
    MemoryCapture,
    MemoryFinding,
    Note,
    Principal,
    RescanRequest,
)

for m in (Investigation, Host, CollectionRun, Finding, IOC, Principal,
          MemoryCapture, MemoryAnalysisRun, MemoryFinding, CustodyEvent,
          Note, RescanRequest, AuditLog):
    admin.site.register(m)

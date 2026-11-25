"""A fixture lab that is in order."""
from fastapi import APIRouter

from engine import labs

router = APIRouter(prefix="/api/labs/fine")


@router.get("")
def fine():
    with labs.context().reading() as con:
        return {"lab": "fine", "events": con.execute("SELECT COUNT(*) FROM events").fetchone()[0]}

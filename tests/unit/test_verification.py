from datetime import datetime, timezone

from models import Verification


def test_make_code():
    res = Verification.make_code()
    assert res >= 100_000
    assert res < 1_000_000


def test_transform_email():
    res = Verification.transform_email(' DJTsucKsbUbbaSdick@epsteinisland.com ')
    assert res == 'djtsucksbubbasdick@epsteinisland.com'


def test_make_entry(session):
    code = Verification.make_code()
    res = Verification.make_entry(session, 'test@example.com', code)
    assert isinstance(res.id, int) == True
    assert res.email == 'test@example.com'
    assert res.code == code
    assert res.when <= datetime.now(timezone.utc)
    assert res.email_sent is None


def test_email_sent_at(session):
    sent = datetime.now(timezone.utc)
    res = Verification.email_sent_at(session, 'test@example.com', sent)
    assert res.email_sent == sent


def test_overwrite_enty(session):
    code = Verification.make_code()
    res = Verification.make_entry(session, 'test@example.com', code)
    assert res.code == code


def test_email_sent_non_existent(session):
    res = Verification.email_sent_at(
        session,
        'nonexistent@example.com',
        datetime.now(timezone.utc))
    
    assert res is None


def test_verify(session):
    code = Verification.make_code()
    Verification.make_entry(
        session,
        'test@example.com',
        code
    )
    res = Verification.verify(
        session,
        'test@example.com',
        code,
        60 * 60 * 1000
    )
    assert res.email == 'test@example.com'
    assert res.code == code


def test_verify_expired(session):
    code = Verification.make_code()
    Verification.make_entry(
        session,
        'bob72@example.com',
        code
    )
    res = Verification.verify(
        session,
        'bob72@example.com',
        code,
        0
    )
    assert res is None


def test_verify_not_found(session):
    res = Verification.verify(
        session,
        'notreal@example.com',
        123_456,
        0
    )
    assert res is None
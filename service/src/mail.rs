//! Durable transactional email delivery over authenticated TLS SMTP.

use std::time::Duration;

use anyhow::{Context, Result};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, Message, SmtpTransport,
    Transport,
};
use postgres::{Client, NoTls};

struct Sender {
    transport: SmtpTransport,
    from: Mailbox,
}

impl Sender {
    fn from_env() -> Result<Option<Self>> {
        let keys = [
            "RSRS_SMTP_HOST",
            "RSRS_SMTP_USERNAME",
            "RSRS_SMTP_PASSWORD",
            "RSRS_MAIL_FROM",
        ];
        let values: Vec<String> = keys
            .iter()
            .map(|key| crate::env::var(key).unwrap_or_default())
            .collect();
        if values.iter().all(|value| value.is_empty()) {
            return Ok(None);
        }
        for (key, value) in keys.iter().zip(&values) {
            anyhow::ensure!(
                !value.trim().is_empty(),
                "{key} is required when SMTP is enabled"
            );
        }
        let port = crate::env::var("RSRS_SMTP_PORT")
            .unwrap_or_else(|_| "587".into())
            .parse::<u16>()
            .context("RSRS_SMTP_PORT must be 465 or 587")?;
        let builder = match port {
            465 => SmtpTransport::relay(&values[0]),
            587 => SmtpTransport::starttls_relay(&values[0]),
            _ => anyhow::bail!("RSRS_SMTP_PORT must be 465 or 587"),
        }
        .context("invalid SMTP TLS host")?;
        Ok(Some(Self {
            transport: builder
                .port(port)
                .timeout(Some(Duration::from_secs(15)))
                .credentials(Credentials::new(values[1].clone(), values[2].clone()))
                .build(),
            from: values[3].parse().context("invalid RSRS_MAIL_FROM")?,
        }))
    }

    fn deliver(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(to.parse()?)
            .subject(subject)
            .body(body.to_owned())?;
        self.transport.send(&message)?;
        Ok(())
    }
}

pub(crate) fn start(url: &str) -> Result<()> {
    let Some(sender) = Sender::from_env()? else {
        eprintln!("mail worker disabled: SMTP is not configured");
        return Ok(());
    };
    let url = url.to_owned();
    std::thread::Builder::new()
        .name("mail-outbox".into())
        .spawn(move || loop {
            if run(&url, &sender).is_err() {
                // SMTP errors may include recipient addresses; never log message bodies or credentials.
                eprintln!("mail worker database connection failed; retrying in 30 seconds");
            }
            std::thread::sleep(Duration::from_secs(30));
        })?;
    Ok(())
}

fn run(url: &str, sender: &Sender) -> Result<()> {
    let mut config: postgres::Config = url.parse()?;
    config.connect_timeout(Duration::from_secs(5));
    let mut db = config.connect(NoTls)?;
    // This dedicated session owns the lock; HTTP uses separate database connections.
    let locked: bool = db
        .query_one("SELECT pg_try_advisory_lock(1869440358)", &[])?
        .get(0);
    if !locked {
        return Ok(());
    }
    loop {
        deliver_next(&mut db, sender)?;
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn deliver_next(db: &mut Client, sender: &Sender) -> Result<()> {
    db.execute("UPDATE mail_outbox SET status='expired', body='' WHERE status='pending' AND
        (expires_at <= NOW() OR NOT EXISTS (SELECT 1 FROM verify_codes v WHERE v.id=mail_outbox.code_id))", &[])?;
    db.execute(
        "UPDATE mail_outbox SET status='failed', body='' WHERE status='pending' AND attempts >= 3",
        &[],
    )?;
    // Ten seconds between attempts keeps this worker below MXroute's 400/hour/mailbox limit.
    let row = db.query_opt("UPDATE mail_outbox SET attempts=attempts+1, attempted_at=NOW(),
        next_attempt_at=NOW()+INTERVAL '60 seconds' WHERE id=(
            SELECT id FROM mail_outbox WHERE status='pending' AND next_attempt_at <= NOW()
            AND expires_at > NOW()+INTERVAL '30 seconds'
            AND NOT EXISTS (SELECT 1 FROM mail_outbox WHERE attempted_at > NOW()-INTERVAL '10 seconds')
            ORDER BY id LIMIT 1)
        RETURNING id, to_addr, subject, body, attempts", &[])?;
    let Some(row) = row else {
        return Ok(());
    };
    let id: i64 = row.get(0);
    let attempts: i32 = row.get(4);
    match sender.deliver(row.get(1), row.get(2), row.get(3)) {
        Ok(()) => {
            db.execute("UPDATE mail_outbox SET status='sent', sent_at=NOW(), body='', last_error='' WHERE id=$1", &[&id])?;
        }
        Err(_) => {
            let terminal = attempts >= 3;
            db.execute(
                "UPDATE mail_outbox SET status=CASE WHEN $2 THEN 'failed' ELSE 'pending' END,
                body=CASE WHEN $2 THEN '' ELSE body END, last_error='SMTP delivery failed',
                next_attempt_at=NOW()+INTERVAL '60 seconds' * attempts WHERE id=$1",
                &[&id, &terminal],
            )?;
            eprintln!("mail outbox {id}: SMTP delivery failed (attempt {attempts})");
        }
    }
    Ok(())
}

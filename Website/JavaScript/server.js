require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieSession = require("cookie-session");
const sqlite3 = require("sqlite3").verbose();

const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DISCORD_REDIRECT_URI,
    SESSION_SECRET
} = process.env;
const PORT = process.env.PORT || 3000;

for (const [name, value] of Object.entries({
    DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI, SESSION_SECRET
})) {
    if (!value) {
        console.error(`В .env не задано: ${name}`);
        process.exit(1);
    }
}

// ---------- База ----------
const db = new sqlite3.Database(path.join(__dirname, "..", "DataBase", "database.db"));
db.configure("busyTimeout", 10000);   // ждать, если синхронизатор пишет в базу

const get = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)))
    );
const all = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)))
    );
const run = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.run(sql, params, function (err) {
            err ? reject(err) : resolve(this);
        })
    );

// ---------- Приложение и сессия ----------
const app = express();

app.disable("x-powered-by");
if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);

app.use(cookieSession({
    name: "session",
    keys: [SESSION_SECRET],
    maxAge: 7 * 24 * 60 * 60 * 1000,                 // 7 дней
    httpOnly: true,
    sameSite: "lax",                                  // нужно, чтобы cookie дожила до возврата из Discord
    secure: process.env.NODE_ENV === "production"     // на https - только по защищённому соединению
}));

// ---------- Вход через Discord ----------
app.get("/auth/login", (req, res) => {
    const state = crypto.randomBytes(16).toString("hex");
    req.session.state = state;

    const url = new URL("https://discord.com/oauth2/authorize");
    url.search = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: DISCORD_REDIRECT_URI,
        response_type: "code",
        scope: "identify",
        state
    }).toString();
    res.redirect(url.toString());
});

app.get("/auth/callback", async (req, res) => {
    const { code, state, error } = req.query;
    const expected = req.session.state;
    req.session.state = null;

    if (error) return res.redirect("/login?error=denied");
    if (!code || !state || state !== expected) return res.redirect("/login?error=failed");

    try {
        const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: "authorization_code",
                code: String(code),
                redirect_uri: DISCORD_REDIRECT_URI
            })
        });
        if (!tokenRes.ok) throw new Error(`token: ${tokenRes.status} ${await tokenRes.text()}`);
        const token = await tokenRes.json();

        const meRes = await fetch("https://discord.com/api/users/@me", {
            headers: { Authorization: `Bearer ${token.access_token}` }
        });
        if (!meRes.ok) throw new Error(`users/@me: ${meRes.status}`);
        const d = await meRes.json();

        // Пускаем тех, кто есть хотя бы в одной из таблиц: ГМ (по числовому Discord ID)
        // или модерация (по логину Discord, регистр не важен). Таблицы наполняет синхронизатор из Google
        const user = await get(
            `SELECT discord_id FROM users_gm WHERE discord_id = ?
             UNION
             SELECT discord_id FROM user_roles_moderation WHERE discord_id = ? COLLATE NOCASE`,
            [d.id, String(d.username || "").toLowerCase()]
        );
        if (!user) return res.redirect("/login?error=not_registered");

        req.session = {
            discordId: d.id,
            username: String(d.username || "").toLowerCase(),   // уникальный логин, ключ сотрудника модерации
            name: d.global_name || d.username,
            avatar: d.avatar
                ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.png?size=128`
                : null
        };
        res.redirect("/");
    } catch (err) {
        console.error("Ошибка входа через Discord:", err);
        res.redirect("/login?error=failed");
    }
});

app.get("/auth/logout", (req, res) => {
    req.session = null;
    res.redirect("/login");
});

// Старые адреса с .html ведут на адреса без него
app.use((req, res, next) => {
    if ((req.method === "GET" || req.method === "HEAD") && req.path.endsWith(".html")) {
        const q = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
        const clean = req.path.slice(0, -5);
        return res.redirect((clean === "/index" ? "/" : clean) + q);
    }
    next();
});

// ---------- Защита: без входа доступны только страница входа и стили ----------
const PUBLIC = new Set(["/login", "/style.css", "/images/logo.png"]);

app.use((req, res, next) => {
    const loggedIn = Boolean(req.session && req.session.discordId && req.session.username);   // старые сессии без username входят заново

    if (req.path === "/login" && loggedIn) return res.redirect("/");
    if (PUBLIC.has(req.path) || loggedIn) return next();

    if (req.path.startsWith("/api/")) return res.status(401).json({ error: "unauthorized" });
    res.redirect("/login");
});

// Ключ сотрудника модерации - логин Discord так, как он записан в users_moderation.
// Ищем без учёта регистра, а дальше везде используем написание из базы: сравнения не зависят от регистра.
app.use(async (req, res, next) => {
    req.modId = null;
    try {
        const username = req.session && req.session.username;
        const isAsset = path.extname(req.path) !== "";
        if (username && !isAsset) {
            const row = await get("SELECT discord_id AS id FROM users_moderation WHERE discord_id = ? COLLATE NOCASE", [username]);
            req.modId = row ? row.id : null;
        }
        next();
    } catch (err) {
        next(err);
    }
});

// ---------- API ----------
app.use(express.json({ limit: "10kb" }));

const fail = (res, code, error) => res.status(code).json({ error });

// Ошибка с понятным сообщением для пользователя (например, «нет прав»)
class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

const safe = fn => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err instanceof HttpError) return fail(res, err.status, err.message);
        console.error(err);
        fail(res, 500, "Ошибка сервера.");
    }
};

// ---------- Константы уровней ----------
const REVIEW_MIN_LEVEL = 50;        // с какого уровня роли можно ставить оценки (REVIEWER)
const TABLE_MIN_LEVEL = 30;         // с какого уровня роли можно видеть общую таблицу (SENIOR_GM)
const REVIEW_EDIT_ANY_LEVEL = 70;   // с какого уровня можно менять чужие оценки (SENIOR_REVIEWER)
const CLOSED_EDIT_LEVEL = 70;       // с какого уровня можно менять оценки в закрытом своде (SENIOR_REVIEWER)

// ---------- Отделы ----------
// Для каждого отдела: свои таблицы, названия ролей на сайте и кто может управлять ролями.
// Подписи ролей (значение) правьте здесь.
const GM = {
    users: "users_gm",
    roles: "roles_gm",
    userRoles: "user_roles_gm",
    idLabel: "Discord ID",
    idError: "Discord ID должен состоять только из цифр.",
    normId: v => String(v || "").trim(),
    validId: v => /^\d{5,25}$/.test(v),
    collate: "",
    labels: {
        GM: "Гейм-Мастер",
        SENIOR_GM: "Ведущий Мастер",
        REVIEWER: "Рецензент",
        FIRST_GM: "Первый Мастер",
        SENIOR_REVIEWER: "Старший Рецензент",
        HEAD_GM: "Главный Гейм-Мастер",
        ADMIN: "Администратор"
    },
    managers: new Set(["HEAD_GM", "SENIOR_REVIEWER", "ADMIN"])   // кто видит страницу «Роли»
};

const MOD = {
    users: "users_moderation",
    roles: "roles_moderation",
    userRoles: "user_roles_moderation",
    useUsername: true,   // ключ сотрудника - логин Discord (req.modId), а не числовой ID
    idLabel: "имени пользователя Discord",
    idError: "Имя пользователя Discord: 2-32 символа, латинские буквы, цифры, «_» и «.».",
    normId: v => String(v || "").trim().replace(/^@/, "").toLowerCase(),
    validId: v => /^[a-z0-9_.]{2,32}$/.test(v),
    collate: " COLLATE NOCASE",   // логины сравниваем без учёта регистра
    needsRole: true,   // в модерации сотрудник - тот, у кого есть хотя бы одна роль, а не просто строка в users
    labels: {
        MODERATOR: "Модератор",
        SENIOR_MODERATOR: "Смотритель Сервера",
        REVIEWER_M: "Рецензент",
        WARDEN: "Смотритель Серверов",
        SENIOR_REVIEWER: "Старший Рецензент",
        HEAD_MODERATOR: "Старший Модератор",
        ADMIN: "Администратор"
    },
    managers: new Set(["HEAD_MODERATOR", "SENIOR_REVIEWER", "ADMIN"])
};

const decorateFor = dept => r => ({ name: r.name, label: dept.labels[r.name] || r.name, level: r.level });

const rolesOfDept = (dept, discordId) => all(
    `SELECT r.name, r.level
     FROM ${dept.userRoles} ur
     JOIN ${dept.roles} r ON r.id = ur.role_id
     WHERE ur.discord_id = ?${dept.collate}
     ORDER BY r.level DESC`,
    [discordId]
);

function permsFor(dept, roles) {
    const names = roles.map(r => r.name);
    return {
        maxLevel: Math.max(0, ...roles.map(r => r.level)),
        isAdmin: names.includes("ADMIN"),
        canManage: names.some(n => dept.managers.has(n))
    };
}

// Выдавать и снимать можно только роли ниже своей (администратор - любые)
const canGrantRole = (p, role) => p.isAdmin || role.level < p.maxLevel;
// Нельзя менять роли тем, кто равен вам или выше (администратор - любым)
const canTouchUser = (p, targetRoles) =>
    p.isAdmin || Math.max(0, ...targetRoles.map(r => r.level)) < p.maxLevel;

// Кто делает запрос в рамках отдела: у ГМ это числовой Discord ID, у модерации логин из базы
const idOf = (dept, req) => (dept.useUsername ? req.modId : req.session.discordId);

// Короткие обёртки для ГМ-отдела: ими пользуются своды, ивенты и оценки (они только для ГМ)
const decorate = decorateFor(GM);
const rolesOf = id => rolesOfDept(GM, id);
const permsOf = roles => permsFor(GM, roles);

// Доступ только для сотрудников ГМ-отдела (своды, оценки, профиль ГМ)
async function requireGm(req, res, next) {
    try {
        const u = await get("SELECT 1 AS ok FROM users_gm WHERE discord_id = ?", [req.session.discordId]);
        if (!u) return fail(res, 403, "Раздел доступен только сотрудникам ГМ-отдела.");
        next();
    } catch (err) {
        next(err);
    }
}

// ----- Кто я -----
// Один запрос для обоих отделов. Поля ГМ остались как были, модерация лежит в поле mod.
app.get("/api/me", safe(async (req, res) => {
    const id = req.session.discordId;
    const gmUser = await get("SELECT ckey FROM users_gm WHERE discord_id = ?", [id]);
    const modRow = req.modId ? await get("SELECT ckey FROM users_moderation WHERE discord_id = ?", [req.modId]) : null;
    const modRoles = modRow ? await rolesOfDept(MOD, req.modId) : [];
    const modUser = modRoles.length ? modRow : null;   // модератор - тот, у кого есть хотя бы одна роль

    if (!gmUser && !modUser) {         // человека убрали из обеих таблиц - выкидываем
        req.session = null;
        return fail(res, 401, "unauthorized");
    }

    const gmRoles = gmUser ? await rolesOfDept(GM, id) : [];
    const gmPerms = permsFor(GM, gmRoles);
    const modPerms = permsFor(MOD, modRoles);

    res.json({
        id,
        name: req.session.name,
        avatar: req.session.avatar,
        ckey: (gmUser || modUser).ckey,
        isGm: gmRoles.length > 0,
        roles: gmRoles.map(decorate),
        canManageRoles: gmPerms.canManage,
        canViewTable: gmPerms.maxLevel >= TABLE_MIN_LEVEL,
        mod: modUser
            ? {
                username: req.modId,
                ckey: modUser.ckey,
                roles: modRoles.map(decorateFor(MOD)),
                canManageRoles: modPerms.canManage,
                canViewTable: modPerms.maxLevel >= MOD_TABLE_MIN_LEVEL
            }
            : null
    });
}));

// Доступ к общей таблице (уровень TABLE_MIN_LEVEL, роли ГМ)
async function requireReviewer(req, res, next) {
    try {
        const perms = permsOf(await rolesOf(req.session.discordId));
        if (perms.maxLevel < TABLE_MIN_LEVEL) {
            return req.originalUrl.startsWith("/api/")
                ? fail(res, 403, "Недостаточно прав.")
                : res.redirect("/");
        }
        next();
    } catch (err) {
        next(err);
    }
}
app.get("/table", requireReviewer);         // страницу видят с уровня TABLE_MIN_LEVEL

// ----- Управление ролями (общий код для обоих отделов) -----
// page - страница, api - префикс API. Для ГМ адреса прежние, для модерации - с приставкой mod.
function mountRoleManagement(dept, { page, api }) {
    const dec = decorateFor(dept);

    async function requireManager(req, res, next) {
        try {
            const perms = permsFor(dept, await rolesOfDept(dept, idOf(dept, req)));
            if (!perms.canManage) {
                return req.originalUrl.startsWith("/api/")
                    ? fail(res, 403, "Недостаточно прав.")
                    : res.redirect("/");
            }
            req.perms = perms;
            next();
        } catch (err) {
            next(err);
        }
    }

    app.get(page, requireManager);      // страницу видят только руководители
    app.use(api, requireManager);

    app.get(api, safe(async (req, res) => {
        const p = req.perms;
        const allRoles = await all(`SELECT name, level FROM ${dept.roles} ORDER BY level`);
        const rows = await all(
            `SELECT u.discord_id AS discordId, u.ckey, r.name, r.level
             FROM ${dept.userRoles} ur
             JOIN ${dept.users} u ON u.discord_id = ur.discord_id${dept.collate}
             JOIN ${dept.roles} r ON r.id = ur.role_id
             ORDER BY u.ckey COLLATE NOCASE, r.level DESC`
        );

        const byUser = new Map();
        for (const row of rows) {
            if (!byUser.has(row.discordId)) {
                byUser.set(row.discordId, { discordId: row.discordId, ckey: row.ckey, roles: [] });
            }
            byUser.get(row.discordId).roles.push({ name: row.name, level: row.level });
        }

        const users = [...byUser.values()].map(u => {
            const touch = canTouchUser(p, u.roles);
            return {
                ...u,
                roles: u.roles.map(r => ({ ...dec(r), canRevoke: touch && canGrantRole(p, r) }))
            };
        });

        res.json({
            assignable: allRoles.filter(r => canGrantRole(p, r)).map(dec),
            users
        });
    }));

    // Общая проверка для выдачи и снятия. Если что-то не так, сама отвечает ошибкой и вернёт null
    async function prepareRoleChange(req, res) {
        const body = req.body || {};
        const idInput = dept.normId(body.discordId);

        if (!dept.validId(idInput)) {
            fail(res, 400, dept.idError);
            return null;
        }
        const role = await get(`SELECT id, name, level FROM ${dept.roles} WHERE name = ?`, [String(body.role || "")]);
        if (!role) {
            fail(res, 400, "Такой роли нет.");
            return null;
        }
        if (!canGrantRole(req.perms, role)) {
            fail(res, 403, "Вы не можете управлять этой ролью.");
            return null;
        }
        // Берём написание из базы, чтобы дальше всё сравнивалось точно
        const target = await get(
            `SELECT discord_id AS id, ckey FROM ${dept.users} WHERE discord_id = ?${dept.collate}`,
            [idInput]
        );
        if (!target) {
            fail(res, 404, `Этого ${dept.idLabel} нет в списке пользователей. Он появится после синхронизации с таблицей Google.`);
            return null;
        }
        const id = target.id;
        if (!canTouchUser(req.perms, await rolesOfDept(dept, id))) {
            fail(res, 403, "Вы не можете менять роли этого пользователя.");
            return null;
        }
        return { id, role, target };
    }

    app.post(`${api}/grant`, safe(async (req, res) => {
        const c = await prepareRoleChange(req, res);
        if (!c) return;

        const r = await run(
            `INSERT OR IGNORE INTO ${dept.userRoles} (discord_id, role_id, granted_by) VALUES (?, ?, ?)`,
            [c.id, c.role.id, idOf(dept, req)]
        );
        res.json({ ok: true, already: r.changes === 0, ckey: c.target.ckey, label: dec(c.role).label });
    }));

    app.post(`${api}/revoke`, safe(async (req, res) => {
        const c = await prepareRoleChange(req, res);
        if (!c) return;

        if (c.role.name === "ADMIN") {
            const admins = await get(
                `SELECT COUNT(*) AS n FROM ${dept.userRoles} ur
                 JOIN ${dept.roles} r ON r.id = ur.role_id WHERE r.name = 'ADMIN'`
            );
            if (admins.n <= 1) return fail(res, 400, "Нельзя снять роль у последнего администратора.");
        }

        const r = await run(
            `DELETE FROM ${dept.userRoles} WHERE discord_id = ?${dept.collate} AND role_id = ?`,
            [c.id, c.role.id]
        );
        if (r.changes === 0) return fail(res, 400, "У пользователя нет этой роли.");
        res.json({ ok: true, ckey: c.target.ckey, label: dec(c.role).label });
    }));
}

mountRoleManagement(GM,  { page: "/roles",     api: "/api/roles" });
mountRoleManagement(MOD, { page: "/roles-mod", api: "/api/mod/roles" });

// ---------- Своды, ивенты и оценки (только ГМ) ----------
// Максимум по каждому из трёх критериев (оценка 1, оценка 2, оценка 3). Меняйте здесь.
const MAX_SCORES = [15, 5, 10];
const MAX_TOTAL = MAX_SCORES.reduce((a, b) => a + b, 0);   // максимум общей оценки
const MAX_COMMENT = 500;            // максимум символов в комментарии

// Один ивент - одна оценка
db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_event_unique ON reviews_gm(event_id)", err => {
    if (err) console.error("Не удалось создать уникальный индекс оценок (есть дубли в reviews_gm?):", err.message);
});

// Транзакции по одной: соединение с базой одно, и параллельные BEGIN его ломают
let txChain = Promise.resolve();
function inTransaction(fn) {
    const job = txChain.then(async () => {
        await run("BEGIN IMMEDIATE");
        try {
            const result = await fn();
            await run("COMMIT");
            return result;
        } catch (err) {
            await run("ROLLBACK").catch(() => {});
            throw err;
        }
    });
    txChain = job.catch(() => {});
    return job;
}

const fmtDate = v => {
    const m = String(v || "").match(/^(\d{4})-(\d{2})-(\d{2})/);
    return m ? `${m[3]}.${m[2]}.${m[1]}` : String(v || "");
};
const round1 = n => Math.round(n * 10) / 10;

const sendPeriods = safe(async (req, res) => {
    const rows = await all(
        `SELECT id, name, is_closed AS closed,
                strftime('%Y-%m', start_date) AS month,
                CASE WHEN date('now', 'localtime') BETWEEN start_date AND end_date THEN 1 ELSE 0 END AS current
         FROM periods
         ORDER BY start_date DESC, id DESC`
    );
    res.json(rows.map(p => ({
        id: p.id,
        name: p.name,
        month: p.month,
        closed: Boolean(p.closed),
        current: Boolean(p.current)
    })));
});

// Своды общие для обоих отделов
app.get("/api/periods", requireGm, sendPeriods);
app.get("/api/mod/periods", requireModMember, sendPeriods);

app.get("/api/events", requireReviewer, safe(async (req, res) => {
    const periodId = Number(req.query.period);
    if (!Number.isInteger(periodId)) return fail(res, 400, "Не указан свод.");

    const me = req.session.discordId;
    const p = permsOf(await rolesOf(me));

    const rows = await all(
        `SELECT e.id, e.event_date, e.server, e.size, e.description, e.host_discord_id,
                hu.ckey AS host,
                pr.is_closed AS closed,
                rv.reviewer_discord_id, ru.ckey AS reviewer,
                rv.score_1, rv.score_2, rv.score_3, rv.total_score, rv.comment
         FROM events e
         JOIN periods pr ON pr.id = e.period_id
         JOIN users_gm hu ON hu.discord_id = e.host_discord_id
         LEFT JOIN reviews_gm rv ON rv.event_id = e.id
         LEFT JOIN users_gm ru ON ru.discord_id = rv.reviewer_discord_id
         WHERE e.period_id = ?
         ORDER BY e.event_number, e.id`,
        [periodId]
    );

    res.json({
        maxScores: MAX_SCORES,
        maxTotal: MAX_TOTAL,
        events: rows.map(r => {
            const rated = r.total_score !== null;
            return {
                id: r.id,
                date: fmtDate(r.event_date),
                size: r.size,
                server: r.server,
                host: r.host,
                desc: r.description,
                reviewer: r.reviewer || null,
                s: rated ? [r.score_1, r.score_2, r.score_3] : null,
                total: rated ? r.total_score : null,
                comment: r.comment || null,
                // Кнопку оценки показываем только тем, кому её можно нажать
                canReview:
                    p.maxLevel >= REVIEW_MIN_LEVEL &&
                    r.host_discord_id !== me &&
                    (!r.closed || p.maxLevel >= CLOSED_EDIT_LEVEL) &&
                    (!r.reviewer_discord_id || r.reviewer_discord_id === me || p.maxLevel >= REVIEW_EDIT_ANY_LEVEL)
            };
        })
    });
}));

app.post("/api/reviews", safe(async (req, res) => {
    const body = req.body || {};
    const eventId = Number(body.eventId);
    const raw = Array.isArray(body.scores) ? body.scores : [];

    if (!Number.isInteger(eventId)) throw new HttpError(400, "Не указан ивент.");
    if (raw.length !== 3 || raw.some((n, i) => typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > MAX_SCORES[i])) {
        throw new HttpError(400, `Оценки должны быть числами: от 0 до ${MAX_SCORES[0]}, от 0 до ${MAX_SCORES[1]} и от 0 до ${MAX_SCORES[2]}.`);
    }
    const rawComment = body.comment == null ? "" : body.comment;
    if (typeof rawComment !== "string") throw new HttpError(400, "Комментарий должен быть текстом.");
    const comment = rawComment.trim();
    if (comment.length > MAX_COMMENT) throw new HttpError(400, `Комментарий не длиннее ${MAX_COMMENT} символов.`);

    const scores = raw.map(round1);
    const total = round1(scores[0] + scores[1] + scores[2]);
    const me = req.session.discordId;

    await inTransaction(async () => {
        const p = permsOf(await rolesOf(me));
        if (p.maxLevel < REVIEW_MIN_LEVEL) throw new HttpError(403, "Оценки могут ставить только рецензенты.");

        const event = await get(
            `SELECT e.id, e.host_discord_id, pr.is_closed AS closed
             FROM events e JOIN periods pr ON pr.id = e.period_id
             WHERE e.id = ?`,
            [eventId]
        );
        if (!event) throw new HttpError(404, "Ивент не найден.");
        if (event.host_discord_id === me) throw new HttpError(403, "Нельзя оценивать свой ивент.");
        if (event.closed && p.maxLevel < CLOSED_EDIT_LEVEL) throw new HttpError(403, "Свод закрыт, оценки менять нельзя.");

        const old = await get(
            "SELECT id, reviewer_discord_id, score_1, score_2, score_3, total_score FROM reviews_gm WHERE event_id = ?",
            [eventId]
        );

        if (old) {
            if (old.reviewer_discord_id !== me && p.maxLevel < REVIEW_EDIT_ANY_LEVEL) {
                throw new HttpError(403, "Этот ивент уже оценил другой рецензент.");
            }
            const changed = old.score_1 !== scores[0] || old.score_2 !== scores[1] ||
                            old.score_3 !== scores[2] || old.total_score !== total;
            if (changed) await run(
                `INSERT INTO review_history_gm
                    (review_id, editor_discord_id,
                     old_score_1, old_score_2, old_score_3, new_score_1, new_score_2, new_score_3,
                     old_total, new_total)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [old.id, me, old.score_1, old.score_2, old.score_3, scores[0], scores[1], scores[2], old.total_score, total]
            );
            await run(
                `UPDATE reviews_gm
                 SET score_1 = ?, score_2 = ?, score_3 = ?, total_score = ?, comment = ?, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`,
                [scores[0], scores[1], scores[2], total, comment || null, old.id]
            );
        } else {
            await run(
                `INSERT INTO reviews_gm (event_id, reviewer_discord_id, score_1, score_2, score_3, total_score, comment)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [eventId, me, scores[0], scores[1], scores[2], total, comment || null]
            );
        }
    });

    res.json({ ok: true, total });
}));

// ---------- Профиль (ГМ) ----------
app.get("/api/profile", requireGm, safe(async (req, res) => {
    const me = req.session.discordId;
    const user = await get("SELECT ckey FROM users_gm WHERE discord_id = ?", [me]);

    const roles = await rolesOf(me);
    const p = permsOf(roles);

    // По каждому своду, где у человека есть ивенты: сколько, сколько оценено, средняя и комментарий к своду
    const periods = await all(
        `SELECT pr.id, pr.name, pr.is_closed AS closed,
                COUNT(e.id) AS events, COUNT(rv.id) AS rated, AVG(rv.total_score) AS avg,
                sc.comment AS summaryComment, au.ckey AS summaryBy
         FROM periods pr
         LEFT JOIN events e ON e.period_id = pr.id AND e.host_discord_id = ?
         LEFT JOIN reviews_gm rv ON rv.event_id = e.id
         LEFT JOIN summary_comments sc ON sc.period_id = pr.id AND sc.host_discord_id = ?
         LEFT JOIN users_gm au ON au.discord_id = sc.author_discord_id
         GROUP BY pr.id
         HAVING COUNT(e.id) > 0
         ORDER BY pr.start_date DESC, pr.id DESC`,
        [me, me]
    );

    const overall = await get(
        `SELECT AVG(rv.total_score) AS avg
         FROM events e JOIN reviews_gm rv ON rv.event_id = e.id
         WHERE e.host_discord_id = ?`,
        [me]
    );

    // Статистика рецензента - только тем, кто может ставить оценки
    let reviewer = null;
    if (p.maxLevel >= REVIEW_MIN_LEVEL) {
        const r = await get(
            "SELECT COUNT(*) AS n, AVG(total_score) AS avg FROM reviews_gm WHERE reviewer_discord_id = ?",
            [me]
        );
        const written = await get(
            "SELECT COUNT(*) AS n FROM reviews_gm WHERE reviewer_discord_id = ? AND comment IS NOT NULL",
            [me]
        );
        const writtenSummary = await get("SELECT COUNT(*) AS n FROM summary_comments WHERE author_discord_id = ?", [me]);
        reviewer = {
            given: r.n,
            avg: r.avg === null ? null : round1(r.avg),
            comments: written.n + writtenSummary.n
        };
    }

    res.json({
        id: me,
        name: req.session.name,
        avatar: req.session.avatar,
        ckey: user.ckey,
        roles: roles.map(decorate),
        maxScores: MAX_SCORES,
        maxTotal: MAX_TOTAL,
        overall: overall.avg === null ? null : round1(overall.avg),
        periods: periods.map(r => ({
            id: r.id,
            name: r.name,
            closed: Boolean(r.closed),
            events: r.events,
            rated: r.rated,
            avg: r.avg === null ? null : round1(r.avg),
            comment: r.summaryComment || null,
            commentBy: r.summaryBy || null
        })),
        reviewer
    });
}));

// ---------- Мои ивенты ----------
app.get("/api/my-events", requireGm, safe(async (req, res) => {
    const periodId = Number(req.query.period);
    if (!Number.isInteger(periodId)) return fail(res, 400, "Не указан свод.");

    const rows = await all(
        `SELECT e.id, e.event_date, e.server, e.size, e.description,
                hu.ckey AS host,
                ru.ckey AS reviewer,
                rv.score_1, rv.score_2, rv.score_3, rv.total_score, rv.comment
         FROM events e
         JOIN users_gm hu ON hu.discord_id = e.host_discord_id
         LEFT JOIN reviews_gm rv ON rv.event_id = e.id
         LEFT JOIN users_gm ru ON ru.discord_id = rv.reviewer_discord_id
         WHERE e.period_id = ? AND e.host_discord_id = ?
         ORDER BY e.event_number, e.id`,
        [periodId, req.session.discordId]
    );

    res.json({
        maxScores: MAX_SCORES,
        maxTotal: MAX_TOTAL,
        events: rows.map(r => {
            const rated = r.total_score !== null;
            return {
                id: r.id,
                date: fmtDate(r.event_date),
                size: r.size,
                server: r.server,
                host: r.host,
                desc: r.description,
                reviewer: r.reviewer || null,
                s: rated ? [r.score_1, r.score_2, r.score_3] : null,
                total: rated ? r.total_score : null,
                comment: r.comment || null
            };
        })
    });
}));

// ---------- Месячный свод ----------
const SUMMARY_COMMENT_MIN_LEVEL = 70;   // кто пишет комментарии к своду (SENIOR_REVIEWER и выше)

db.run(
    `CREATE TABLE IF NOT EXISTS summary_comments (
        period_id INTEGER NOT NULL,
        host_discord_id TEXT NOT NULL,
        comment TEXT NOT NULL,
        author_discord_id TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (period_id, host_discord_id),
        FOREIGN KEY (period_id) REFERENCES periods(id),
        FOREIGN KEY (host_discord_id) REFERENCES users_gm(discord_id)
    )`,
    err => { if (err) console.error("Не удалось создать таблицу summary_comments:", err.message); }
);

app.get("/api/summary", requireGm, safe(async (req, res) => {
    // Либо один свод (?period=ID), либо целый месяц из нескольких сводов (?month=ГГГГ-ММ)
    const month = String(req.query.month || "");
    const byMonth = /^\d{4}-\d{2}$/.test(month);
    const periodId = Number(req.query.period);
    if (!byMonth && !Number.isInteger(periodId)) return fail(res, 400, "Не указан свод.");

    const scope = byMonth
        ? "e.period_id IN (SELECT id FROM periods WHERE strftime('%Y-%m', start_date) = ?)"
        : "e.period_id = ?";
    const param = byMonth ? month : periodId;

    const me = req.session.discordId;
    const p = permsOf(await rolesOf(me));

    // Средняя общая оценка по всем оценённым ивентам проводящего (за свод или за весь месяц)
    const rows = await all(
        `SELECT e.host_discord_id AS hostId, u.ckey AS host,
                COUNT(*) AS events,
                COUNT(rv.id) AS rated,
                AVG(rv.total_score) AS avg
         FROM events e
         JOIN users_gm u ON u.discord_id = e.host_discord_id
         LEFT JOIN reviews_gm rv ON rv.event_id = e.id
         WHERE ${scope}
         GROUP BY e.host_discord_id
         ORDER BY AVG(rv.total_score) IS NULL, AVG(rv.total_score) DESC, u.ckey COLLATE NOCASE`,
        [param]
    );

    const byHost = new Map();
    if (byMonth) {
        // За месяц показываем комментарии всех его сводов вместе, с названием свода
        const comments = await all(
            `SELECT sc.host_discord_id AS hostId, sc.comment, pr.name AS period
             FROM summary_comments sc
             JOIN periods pr ON pr.id = sc.period_id
             WHERE strftime('%Y-%m', pr.start_date) = ?
             ORDER BY pr.start_date, pr.id`,
            [month]
        );
        for (const c of comments) {
            const text = `${c.period}: ${c.comment}`;
            const cur = byHost.get(c.hostId);
            byHost.set(c.hostId, { comment: cur ? `${cur.comment}\n\n${text}` : text, author: null });
        }
    } else {
        const comments = await all(
            `SELECT sc.host_discord_id AS hostId, sc.comment, au.ckey AS author
             FROM summary_comments sc
             LEFT JOIN users_gm au ON au.discord_id = sc.author_discord_id
             WHERE sc.period_id = ?`,
            [periodId]
        );
        for (const c of comments) byHost.set(c.hostId, { comment: c.comment, author: c.author });
    }

    res.json({
        maxScores: MAX_SCORES,
        maxTotal: MAX_TOTAL,
        rows: rows.map(r => {
            const c = byHost.get(r.hostId);
            return {
                hostId: r.hostId,
                host: r.host,
                events: r.events,
                rated: r.rated,
                avg: r.avg === null ? null : round1(r.avg),
                comment: c ? c.comment : null,
                commentBy: c ? c.author : null,
                isMe: r.hostId === me,
                // Писать можно только в конкретный свод, в месячном виде комментарии только читаются
                canComment: !byMonth && p.maxLevel >= SUMMARY_COMMENT_MIN_LEVEL && (r.hostId !== me || p.isAdmin)
            };
        })
    });
}));

app.post("/api/summary/comment", requireGm, safe(async (req, res) => {
    const body = req.body || {};
    const periodId = Number(body.periodId);
    const hostId = String(body.hostId || "").trim();
    const raw = body.comment == null ? "" : body.comment;

    if (!Number.isInteger(periodId) || !/^\d{5,25}$/.test(hostId)) throw new HttpError(400, "Некорректный запрос.");
    if (typeof raw !== "string") throw new HttpError(400, "Комментарий должен быть текстом.");
    const comment = raw.trim();
    if (comment.length > MAX_COMMENT) throw new HttpError(400, `Комментарий не длиннее ${MAX_COMMENT} символов.`);

    const me = req.session.discordId;
    const p = permsOf(await rolesOf(me));
    if (p.maxLevel < SUMMARY_COMMENT_MIN_LEVEL) {
        throw new HttpError(403, "Комментарии к своду могут писать старшие рецензенты и выше.");
    }
    if (hostId === me && !p.isAdmin) throw new HttpError(403, "Нельзя комментировать свой свод.");

    const has = await get(
        "SELECT 1 AS ok FROM events WHERE period_id = ? AND host_discord_id = ? LIMIT 1",
        [periodId, hostId]
    );
    if (!has) throw new HttpError(404, "У этого проводящего нет ивентов в выбранном своде.");

    if (!comment) {      // пустой текст - убираем комментарий
        await run("DELETE FROM summary_comments WHERE period_id = ? AND host_discord_id = ?", [periodId, hostId]);
    } else {
        await run(
            `INSERT INTO summary_comments (period_id, host_discord_id, comment, author_discord_id)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(period_id, host_discord_id) DO UPDATE SET
                comment = excluded.comment,
                author_discord_id = excluded.author_discord_id,
                updated_at = CURRENT_TIMESTAMP`,
            [periodId, hostId, comment, me]
        );
    }
    res.json({ ok: true });
}));

// ---------- Оценки модераторов ----------
// Одна оценка на модератора за свод (период). Все значения ниже правьте по мере уточнения критериев.
const REVIEWS_MOD = "reviews_moderation";          // таблица оценок (поменяйте, если называется иначе)
const HISTORY_MOD = "review_history_moderation";   // история изменений оценок (поменяйте, если называется иначе)
const MOD_SERVER_COLUMN = "server";                // колонка сервера в users_moderation (если её нет, сервер будет пустым)
const MOD_SCORE_LABELS = ["Активность", "Общение", "Разбор", "Личная оценка"];
const MOD_MAX_SCORES = [5, 10, 5, 5];
const MOD_MAX_TOTAL = MOD_MAX_SCORES.reduce((a, b) => a + b, 0);
const MOD_AREAS = ["АХелпы", "Отклики", "Жалобы", "Обжалования", "Другое"];   // «Основная деятельность»

// Уровни ролей модерации (пока скопированы с ГМ, поправьте, когда роли будут обновлены)
const MOD_TABLE_MIN_LEVEL = 30;           // с какого уровня видна общая таблица
const MOD_REVIEW_MIN_LEVEL = 50;          // с какого уровня можно ставить оценки
const MOD_REVIEW_EDIT_ANY_LEVEL = 70;     // с какого уровня можно менять чужие оценки
const MOD_CLOSED_EDIT_LEVEL = 70;         // с какого уровня можно менять оценки в закрытом своде

let modHasServer = false;
db.all("PRAGMA table_info(users_moderation)", (err, cols) => {
    modHasServer = !err && Array.isArray(cols) && cols.some(c => c.name === MOD_SERVER_COLUMN);
    if (!modHasServer) console.warn(`В users_moderation нет колонки "${MOD_SERVER_COLUMN}": в таблице оценки модерации сервер будет пустым.`);
});

// При старте проверяем, что таблицы и колонки на месте, и пишем в консоль, чего не хватает
function checkTable(name, needed) {
    db.all(`PRAGMA table_info(${name})`, (err, cols) => {
        const have = new Set((cols || []).map(c => c.name));
        if (err || !have.size) return console.error(`Таблица ${name} не найдена: оценки модераторов работать не будут.`);
        const missing = needed.filter(c => !have.has(c));
        if (missing.length) console.error(`В таблице ${name} нет колонок: ${missing.join(", ")}`);
    });
}
checkTable(REVIEWS_MOD, [
    "id", "period_id", "moderator_discord_id", "reviewer_discord_id",
    "score_1", "score_2", "score_3", "score_4", "total_score", "main_area", "comment", "updated_at"
]);
checkTable(HISTORY_MOD, [
    "review_id", "editor_discord_id",
    "old_score_1", "old_score_2", "old_score_3", "old_score_4", "old_main_area",
    "new_score_1", "new_score_2", "new_score_3", "new_score_4", "new_main_area",
    "old_total", "new_total"
]);

// Одна оценка на модератора в одном своде
db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_mod_unique ON ${REVIEWS_MOD}(moderator_discord_id, period_id)`, err => {
    if (err) console.error(`Не удалось создать уникальный индекс оценок модераторов (нет колонки period_id или есть дубли?): ${err.message}`);
});

async function requireModTableAccess(req, res, next) {
    try {
        const perms = permsFor(MOD, await rolesOfDept(MOD, req.modId));
        if (perms.maxLevel < MOD_TABLE_MIN_LEVEL) {
            return req.originalUrl.startsWith("/api/")
                ? fail(res, 403, "Недостаточно прав.")
                : res.redirect("/");
        }
        next();
    } catch (err) {
        next(err);
    }
}
app.get("/table-mod", requireModTableAccess);
app.use("/api/mod/ratings", requireModTableAccess);

// В таблице все, кто есть в users_moderation (роль не обязательна); оценки - за выбранный свод
app.get("/api/mod/ratings", safe(async (req, res) => {
    const periodId = Number(req.query.period);
    if (!Number.isInteger(periodId)) return fail(res, 400, "Не указан свод.");

    const period = await get("SELECT is_closed AS closed FROM periods WHERE id = ?", [periodId]);
    if (!period) return fail(res, 404, "Свод не найден.");

    const me = req.modId;
    const p = permsFor(MOD, await rolesOfDept(MOD, me));
    const serverSel = modHasServer ? `u.${MOD_SERVER_COLUMN} AS server` : "NULL AS server";

    const rows = await all(
        `SELECT u.discord_id AS discordId, u.ckey, ${serverSel},
                rv.reviewer_discord_id AS reviewerId, ru.ckey AS reviewer,
                rv.score_1, rv.score_2, rv.score_3, rv.score_4, rv.total_score,
                rv.main_area AS area, rv.comment
         FROM users_moderation u
         LEFT JOIN ${REVIEWS_MOD} rv ON rv.moderator_discord_id = u.discord_id AND rv.period_id = ?
         LEFT JOIN users_moderation ru ON ru.discord_id = rv.reviewer_discord_id
         ORDER BY u.ckey COLLATE NOCASE`,
        [periodId]
    );

    res.json({
        labels: MOD_SCORE_LABELS,
        maxScores: MOD_MAX_SCORES,
        maxTotal: MOD_MAX_TOTAL,
        areas: MOD_AREAS,
        closed: Boolean(period.closed),
        rows: rows.map(r => {
            const rated = r.total_score !== null;
            return {
                id: r.discordId,
                ckey: r.ckey,
                server: r.server || null,
                reviewer: r.reviewer || null,
                s: rated ? [r.score_1, r.score_2, r.score_3, r.score_4] : null,
                total: rated ? r.total_score : null,
                area: r.area || null,
                comment: r.comment || null,
                // Кнопку оценки показываем только тем, кому её можно нажать
                canReview:
                    p.maxLevel >= MOD_REVIEW_MIN_LEVEL &&
                    r.discordId !== me &&
                    (!period.closed || p.maxLevel >= MOD_CLOSED_EDIT_LEVEL) &&
                    (!r.reviewerId || r.reviewerId === me || p.maxLevel >= MOD_REVIEW_EDIT_ANY_LEVEL)
            };
        })
    });
}));

app.post("/api/mod/reviews", safe(async (req, res) => {
    const body = req.body || {};
    const periodId = Number(body.periodId);
    const moderatorInput = MOD.normId(body.moderatorId);
    const raw = Array.isArray(body.scores) ? body.scores : [];

    if (!Number.isInteger(periodId)) throw new HttpError(400, "Не указан свод.");
    if (!MOD.validId(moderatorInput)) throw new HttpError(400, "Не указан модератор.");
    if (raw.length !== MOD_MAX_SCORES.length ||
        raw.some((n, i) => typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > MOD_MAX_SCORES[i])) {
        const rules = MOD_SCORE_LABELS.map((l, i) => `${l} от 0 до ${MOD_MAX_SCORES[i]}`).join(", ");
        throw new HttpError(400, `Оценки должны быть числами: ${rules}.`);
    }
    const area = String(body.area || "");
    if (!MOD_AREAS.includes(area)) throw new HttpError(400, "Выберите основную деятельность.");

    const rawComment = body.comment == null ? "" : body.comment;
    if (typeof rawComment !== "string") throw new HttpError(400, "Комментарий должен быть текстом.");
    const comment = rawComment.trim();
    if (comment.length > MAX_COMMENT) throw new HttpError(400, `Комментарий не длиннее ${MAX_COMMENT} символов.`);

    const scores = raw.map(round1);
    const total = round1(scores.reduce((a, b) => a + b, 0));
    const me = req.modId;

    await inTransaction(async () => {
        const p = permsFor(MOD, await rolesOfDept(MOD, me));
        if (p.maxLevel < MOD_REVIEW_MIN_LEVEL) throw new HttpError(403, "Оценки могут ставить только рецензенты.");
        // Логин берём в том написании, как он записан в users_moderation
        const target = await get("SELECT discord_id AS id FROM users_moderation WHERE discord_id = ? COLLATE NOCASE", [moderatorInput]);
        if (!target) throw new HttpError(404, "Модератор не найден.");
        const moderatorId = target.id;
        if (moderatorId === me) throw new HttpError(403, "Нельзя оценивать самого себя.");

        const period = await get("SELECT is_closed AS closed FROM periods WHERE id = ?", [periodId]);
        if (!period) throw new HttpError(404, "Свод не найден.");
        if (period.closed && p.maxLevel < MOD_CLOSED_EDIT_LEVEL) throw new HttpError(403, "Свод закрыт, оценки менять нельзя.");

        const old = await get(
            `SELECT id, reviewer_discord_id, score_1, score_2, score_3, score_4, total_score, main_area
             FROM ${REVIEWS_MOD} WHERE moderator_discord_id = ? AND period_id = ?`,
            [moderatorId, periodId]
        );

        if (old) {
            if (old.reviewer_discord_id !== me && p.maxLevel < MOD_REVIEW_EDIT_ANY_LEVEL) {
                throw new HttpError(403, "Этого модератора уже оценил другой рецензент.");
            }
            // В историю пишем изменения оценок и основной деятельности (комментарий, как и у ГМ, не логируется)
            const changed = old.score_1 !== scores[0] || old.score_2 !== scores[1] ||
                            old.score_3 !== scores[2] || old.score_4 !== scores[3] ||
                            old.total_score !== total || old.main_area !== area;
            if (changed) await run(
                `INSERT INTO ${HISTORY_MOD}
                    (review_id, editor_discord_id,
                     old_score_1, old_score_2, old_score_3, old_score_4, old_main_area,
                     new_score_1, new_score_2, new_score_3, new_score_4, new_main_area,
                     old_total, new_total)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [old.id, me,
                 old.score_1, old.score_2, old.score_3, old.score_4, old.main_area,
                 scores[0], scores[1], scores[2], scores[3], area,
                 old.total_score, total]
            );
            await run(
                `UPDATE ${REVIEWS_MOD}
                 SET score_1 = ?, score_2 = ?, score_3 = ?, score_4 = ?, total_score = ?,
                     main_area = ?, comment = ?, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`,
                [...scores, total, area, comment || null, old.id]
            );
        } else {
            await run(
                `INSERT INTO ${REVIEWS_MOD}
                    (period_id, moderator_discord_id, reviewer_discord_id,
                     score_1, score_2, score_3, score_4, total_score, main_area, comment)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [periodId, moderatorId, me, ...scores, total, area, comment || null]
            );
        }
    });

    res.json({ ok: true, total });
}));

// ---------- Месячный свод модераторов ----------
// Открыт всем, у кого есть роль модерации (как свод у ГМ - всем ГМ); в списке все из users_moderation
async function requireModMember(req, res, next) {
    try {
        if (!(await isMember(MOD, req.modId))) {
            return fail(res, 403, "Раздел доступен только сотрудникам модерации.");
        }
        next();
    } catch (err) {
        next(err);
    }
}

app.get("/api/mod/summary", requireModMember, safe(async (req, res) => {
    // Либо один свод (?period=ID), либо целый месяц из нескольких сводов (?month=ГГГГ-ММ)
    const month = String(req.query.month || "");
    const byMonth = /^\d{4}-\d{2}$/.test(month);
    const periodId = Number(req.query.period);
    if (!byMonth && !Number.isInteger(periodId)) return fail(res, 400, "Не указан свод.");

    const scope = byMonth
        ? "rv.period_id IN (SELECT id FROM periods WHERE strftime('%Y-%m', start_date) = ?)"
        : "rv.period_id = ?";
    const param = byMonth ? month : periodId;
    const me = req.modId;

    const periodsTotal = byMonth
        ? (await get("SELECT COUNT(*) AS n FROM periods WHERE strftime('%Y-%m', start_date) = ?", [month])).n
        : 1;

    // Средняя общая оценка модератора за свод (или за все своды месяца) и его основная деятельность
    const rows = await all(
        `SELECT u.discord_id AS hostId, u.ckey AS host,
                COUNT(rv.id) AS rated,
                AVG(rv.total_score) AS avg,
                GROUP_CONCAT(DISTINCT rv.main_area) AS areas
         FROM users_moderation u
         LEFT JOIN ${REVIEWS_MOD} rv ON rv.moderator_discord_id = u.discord_id AND ${scope}
         GROUP BY u.discord_id
         ORDER BY AVG(rv.total_score) IS NULL, AVG(rv.total_score) DESC, u.ckey COLLATE NOCASE`,
        [param]
    );

    // Комментарий - это комментарий самой оценки
    const byHost = new Map();
    if (byMonth) {
        // За месяц показываем комментарии всех сводов вместе, с названием свода
        const comments = await all(
            `SELECT rv.moderator_discord_id AS hostId, rv.comment, pr.name AS period
             FROM ${REVIEWS_MOD} rv
             JOIN periods pr ON pr.id = rv.period_id
             WHERE rv.comment IS NOT NULL AND strftime('%Y-%m', pr.start_date) = ?
             ORDER BY pr.start_date, pr.id`,
            [month]
        );
        for (const c of comments) {
            const text = `${c.period}: ${c.comment}`;
            const cur = byHost.get(c.hostId);
            byHost.set(c.hostId, { comment: cur ? `${cur.comment}\n\n${text}` : text, author: null });
        }
    } else {
        const comments = await all(
            `SELECT rv.moderator_discord_id AS hostId, rv.comment, ru.ckey AS author
             FROM ${REVIEWS_MOD} rv
             LEFT JOIN users_moderation ru ON ru.discord_id = rv.reviewer_discord_id
             WHERE rv.comment IS NOT NULL AND rv.period_id = ?`,
            [periodId]
        );
        for (const c of comments) byHost.set(c.hostId, { comment: c.comment, author: c.author });
    }

    res.json({
        maxTotal: MOD_MAX_TOTAL,
        periodsTotal,
        rows: rows.map(r => {
            const c = byHost.get(r.hostId);
            return {
                hostId: r.hostId,
                host: r.host,
                rated: r.rated,
                avg: r.avg === null ? null : round1(r.avg),
                areas: r.areas ? r.areas.split(",") : [],
                comment: c ? c.comment : null,
                commentBy: c ? c.author : null,
                isMe: r.hostId === me
            };
        })
    });
}));

// ---------- Профиль модератора ----------
app.get("/api/mod/profile", safe(async (req, res) => {
    const me = req.modId;
    const roles = await rolesOfDept(MOD, me);
    if (!roles.length) return fail(res, 403, "Раздел доступен только сотрудникам модерации.");
    const p = permsFor(MOD, roles);

    const user = await get("SELECT ckey FROM users_moderation WHERE discord_id = ?", [me]);

    // Все оценки, которые получил этот модератор, от новых сводов к старым
    const rows = await all(
        `SELECT pr.name AS period, pr.is_closed AS closed,
                rv.score_1, rv.score_2, rv.score_3, rv.score_4, rv.total_score,
                rv.main_area AS area, rv.comment,
                ru.ckey AS reviewer
         FROM ${REVIEWS_MOD} rv
         JOIN periods pr ON pr.id = rv.period_id
         LEFT JOIN users_moderation ru ON ru.discord_id = rv.reviewer_discord_id
         WHERE rv.moderator_discord_id = ?
         ORDER BY pr.start_date DESC, pr.id DESC`,
        [me]
    );

    // Самая частая основная деятельность (при равенстве - более свежая)
    const counts = new Map();
    for (const r of rows) if (r.area) counts.set(r.area, (counts.get(r.area) || 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];

    // Статистика рецензента - только тем, кто может ставить оценки
    let reviewer = null;
    if (p.maxLevel >= MOD_REVIEW_MIN_LEVEL) {
        const given = await get(
            `SELECT COUNT(*) AS n, AVG(total_score) AS avg FROM ${REVIEWS_MOD} WHERE reviewer_discord_id = ?`,
            [me]
        );
        const written = await get(
            `SELECT COUNT(*) AS n FROM ${REVIEWS_MOD} WHERE reviewer_discord_id = ? AND comment IS NOT NULL`,
            [me]
        );
        reviewer = {
            given: given.n,
            avg: given.avg === null ? null : round1(given.avg),
            comments: written.n
        };
    }

    res.json({
        id: me,
        name: req.session.name,
        avatar: req.session.avatar,
        ckey: user ? user.ckey : null,
        roles: roles.map(decorateFor(MOD)),
        labels: MOD_SCORE_LABELS,
        maxScores: MOD_MAX_SCORES,
        maxTotal: MOD_MAX_TOTAL,
        overall: rows.length ? round1(rows.reduce((s, r) => s + r.total_score, 0) / rows.length) : null,
        topArea: top ? top[0] : null,
        reviews: rows.map(r => ({
            period: r.period,
            closed: Boolean(r.closed),
            area: r.area || null,
            s: [r.score_1, r.score_2, r.score_3, r.score_4],
            total: r.total_score,
            reviewer: r.reviewer || null,
            comment: r.comment || null
        })),
        reviewer
    });
}));

// ---------- Главные страницы отделов ----------
// После входа открывается «/»: если человек есть в обоих отделах, приоритет у ГМ.
// Переключаться между отделами можно кнопкой на главной странице.
const isMember = async (dept, discordId) =>
    Boolean(await get(
        dept.needsRole
            ? `SELECT 1 AS ok FROM ${dept.userRoles} WHERE discord_id = ?${dept.collate} LIMIT 1`
            : `SELECT 1 AS ok FROM ${dept.users} WHERE discord_id = ?${dept.collate}`,
        [discordId]
    ));

// Страницы отдела открываются только его сотрудникам, остальных отправляем на «/»
const requireDeptPage = dept => async (req, res, next) => {
    try {
        if (await isMember(dept, idOf(dept, req))) return next();
        res.redirect("/");
    } catch (err) {
        next(err);
    }
};

app.get("/", safe(async (req, res) => {
    if (await isMember(GM, req.session.discordId)) return res.redirect("/main");
    if (await isMember(MOD, req.modId)) return res.redirect("/main_mod");
    req.session = null;                     // человека убрали из обеих таблиц
    res.redirect("/login?error=not_registered");
}));

app.get("/index", (req, res) => res.redirect("/"));   // старые ссылки и закладки

app.get(["/main", "/profile", "/summary", "/my-events"], requireDeptPage(GM));
app.get(["/main_mod", "/summary-mod", "/mod-summary", "/profile-mod"], requireDeptPage(MOD));

// ---------- Сайт ----------
// Отдаём ТОЛЬКО папку с фронтендом, не корень проекта (там .env и база)
app.use("/images", express.static(path.join(__dirname, "..", "Images")));
app.use(express.static(path.join(__dirname, "..", "HTML-CSS"), { extensions: ["html"] }));

app.listen(PORT, () => console.log(`Сайт: http://localhost:${PORT}`));
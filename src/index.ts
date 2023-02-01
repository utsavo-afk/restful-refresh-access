import express, { json, NextFunction, Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { hash, verify } from 'argon2';
import { JwtPayload, sign, verify as verifyToken } from 'jsonwebtoken';
import { config } from 'dotenv-safe';
import cookieParser from 'cookie-parser';
import { validateReq } from '@src/middleware/validateReq';
import { prisma as task } from '@src/utils/prisma';
import { createUserSchema, loginUserSchema } from '@src/utils/schema';
import { tokenChecker } from './middleware/tokenCheck';

const app = express();
app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(morgan('tiny'));
app.use(cookieParser());
app.use(json());
app.use(helmet({}));
config();

app.get('/ping', (req: Request, res: Response) => {
	res.send({ status: 'running' });
});

app.get('/protected', tokenChecker, (req: Request, res: Response) => {
	res.send({ secret: 'data' });
});

// users
// create user
app.post(
	'/api/users',
	validateReq(createUserSchema),
	async (req: Request, res: Response, next: NextFunction) => {
		try {
			const data = {
				...req.body,
				createdAt: new Date(),
			};
			data.password = await hash(data.password);
			await task.user.create({
				data,
			});
			return res.status(200).send({ status: 'success' });
		} catch (error) {
			return next(error);
		}
	}
);

// login
app.post(
	'/api/auth',
	validateReq(loginUserSchema),
	async (req: Request, res: Response, next: NextFunction) => {
		try {
			const { password, uniqueIdentifier } = req.body;
			const $user = await task.user.findFirst({
				where: {
					OR: [{ email: uniqueIdentifier }, { username: uniqueIdentifier }],
				},
			});

			if (!$user || !(await verify($user.password, password)))
				throw new Error('authentication failed');

			const refreshToken = sign(
				{ uid: $user.id },
				process.env.REFRESH_TOKEN_SECRET as string,
				{ expiresIn: '7d' }
			);
			const accessToken = sign(
				{ uid: $user.id },
				process.env.ACCESS_TOKEN_SECRET as string,
				{ expiresIn: '10m' }
			);
			res.cookie('x-refresh-token', refreshToken, {
				httpOnly: true,
				sameSite: 'none',
				secure: true,
				maxAge: 24 * 60 * 60 * 1000,
			});

			return res.send({ accessToken });
		} catch (error) {
			return next(error);
		}
	}
);

app.get(
	'/api/auth',
	async (req: Request, res: Response, next: NextFunction) => {
		try {
			// check refresh token
			if (!req.cookies?.['x-refresh-token']) throw new Error('Unauthorized');
			const refreshToken = req.cookies?.['x-refresh-token'];
			const decoded = verifyToken(
				refreshToken,
				process.env.REFRESH_TOKEN_SECRET as string
			);
			if (!decoded) throw new Error('invalid refreshToken');
			// console.log(decoded);
			// generate new access_token
			const accessToken = sign(
				{ uid: (decoded as JwtPayload).uid },
				process.env.ACCESS_TOKEN_SECRET as string,
				{ expiresIn: '10m' }
			);
			// send access_token to client
			res.send({ accessToken });
		} catch (error) {
			return next(error);
		}
	}
);

app.use((err: unknown, req: Request, res: Response) => {
	res.status(500).render('error', { error: err, errName: (err as Error).name });
});

app.listen(3000, () => console.log(`Server ready @ http://localhost:3000`));

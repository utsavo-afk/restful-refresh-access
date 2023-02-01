import { Request, Response, NextFunction } from 'express';
import { JwtPayload, sign, verify } from 'jsonwebtoken';
import { config } from 'dotenv-safe';
config();

export const tokenChecker = async (
	req: Request,
	res: Response,
	next: NextFunction
) => {
	try {
		console.log('headers: ', req.headers);

		if (!req.cookies?.['x-refresh-token']) throw new Error('Unauthorized');
		const refreshToken = req.cookies['x-refresh-token'];
		const decodedRefresh = verify(
			refreshToken,
			process.env.REFRESH_TOKEN_SECRET as string
		);
		if (!decodedRefresh) throw new Error('Unauthorized');

		// check access token
		const token = req.headers.authorization?.split(' ')[1] as string;
		const decodedAcessToken = verify(
			token,
			process.env.ACCESS_TOKEN_SECRET as string,
			{ ignoreExpiration: true }
		);
		if (!decodedAcessToken) {
			const accessToken = sign(
				{ uid: (decodedRefresh as JwtPayload).uid },
				process.env.REFRESH_TOKEN_SECRET as string
			);
			req.headers.authorization = 'Bearer ' + accessToken;
		}
		return next();
	} catch (error) {
		return next(error);
	}
};

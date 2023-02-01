import { z } from 'zod';

export const loginUserSchema = z.object({
	body: z.object({
		username: z.string().optional(),
		uniqueIdentifier: z.string(),
	}),
	query: z.object({}).optional(),
	params: z.object({}).optional(),
});

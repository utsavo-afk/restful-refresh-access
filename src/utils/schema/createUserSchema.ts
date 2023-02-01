import { z } from 'zod';

export const createUserSchema = z.object({
	body: z.object({
		firstName: z.string({}).min(1).max(20),
		lastName: z.string({}).min(1).max(20),
		email: z.string().email(),
		password: z.string().min(5).max(10),
	}),
	query: z.object({}).optional(),
	params: z.object({}).optional(),
});

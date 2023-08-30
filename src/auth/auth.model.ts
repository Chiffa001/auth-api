import { ApiProperty } from '@nestjs/swagger';
import { Tokens } from './types/tokens';

export class AuthModel implements Pick<Tokens, 'accessToken'> {
  @ApiProperty({ example: 'token', description: 'token' })
  accessToken: string;
}

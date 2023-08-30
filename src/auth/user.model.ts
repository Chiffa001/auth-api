import { ApiProperty } from '@nestjs/swagger';
import { UserInfo } from './types/user';

export class UserModel implements UserInfo {
  @ApiProperty({ example: 1, description: 'id' })
  id: number;

  @ApiProperty({ example: 'name', description: 'name' })
  name: string;

  @ApiProperty({ example: 'email', description: 'email' })
  email: string;
}

import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsEmail } from 'class-validator';

export class AuthDto {
  @ApiProperty({ example: 'user@mail.ru', description: 'email' })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'qwerty', description: 'password' })
  @IsNotEmpty()
  @IsString()
  password: string;
}

import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Public } from './../common/decorators/public';
import { AuthService } from './auth.service';
import { GetCurrentUserId, GetCurrentUser } from 'src/common/decorators';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types/tokens';
import { RefreshTokenGuard } from 'src/common/guards/refresh-token.guard';
import { Response } from 'express';
import { REFRESH_TOKEN_COOKIE_NAME } from 'src/constants/auth';
import { ApiHeader, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthModel } from './auth.model';
import { UserModel } from './user.model';
import { UserInfo } from './types/user';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @ApiOperation({ summary: 'Registration' })
  @ApiResponse({ status: 200, type: AuthModel })
  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  async signupLocal(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<Pick<Tokens, 'accessToken'>> {
    const { refreshToken: updatedRefreshToken, accessToken } =
      await this.authService.signupLocal(dto);
    response.cookie(REFRESH_TOKEN_COOKIE_NAME, updatedRefreshToken, {
      httpOnly: true,
    });
    return {
      accessToken,
    };
  }

  @ApiOperation({ summary: 'Login' })
  @ApiResponse({ status: 200, type: AuthModel })
  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  async signinLocal(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<Pick<Tokens, 'accessToken'>> {
    const { refreshToken: updatedRefreshToken, accessToken } =
      await this.authService.signinLocal(dto);
    response.cookie(REFRESH_TOKEN_COOKIE_NAME, updatedRefreshToken, {
      httpOnly: true,
    });
    return { accessToken };
  }

  @ApiHeader({ name: 'Authorization' })
  @ApiOperation({ summary: 'Logout' })
  @ApiResponse({ status: 200, type: Boolean })
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }

  @ApiOperation({ summary: 'Refresh tokens' })
  @ApiResponse({ status: 200, type: AuthModel })
  @Public()
  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
    @Res({ passthrough: true }) response: Response,
  ): Promise<Pick<Tokens, 'accessToken'>> {
    const { refreshToken: updatedRefreshToken, accessToken } =
      await this.authService.refreshTokens(userId, refreshToken);
    response.cookie(REFRESH_TOKEN_COOKIE_NAME, updatedRefreshToken, {
      httpOnly: true,
    });
    return {
      accessToken,
    };
  }

  @ApiHeader({ name: 'Authorization' })
  @ApiOperation({ summary: 'Get user info' })
  @ApiResponse({ status: 200, type: UserModel })
  @Get('/info')
  @HttpCode(HttpStatus.OK)
  getUserInfo(@GetCurrentUserId() userId: number): Promise<UserInfo> {
    return this.authService.getUserInfo(userId);
  }
}

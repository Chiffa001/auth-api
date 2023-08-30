import { AuthGuard } from '@nestjs/passport';
import { JWT_REFRESH } from 'src/constants/auth';

export class RefreshTokenGuard extends AuthGuard(JWT_REFRESH) {
  constructor() {
    super();
  }
}

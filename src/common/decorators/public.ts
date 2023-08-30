import { SetMetadata } from '@nestjs/common';
import { IS_PUBLIC } from 'src/constants/public';

export const Public = () => SetMetadata(IS_PUBLIC, true);

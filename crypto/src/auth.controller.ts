import {
  Controller,
  Post,
  Body,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { AuthService, InternetIdentityAuthResponse } from './auth.service';

interface AuthRequestBody {
  response: InternetIdentityAuthResponse;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('verify')
  verify(@Body() authRequestBody: AuthRequestBody) {
    const isValid = this.authService.verifyInternetIdentityAuth(
      authRequestBody.response,
    );

    if (!isValid) {
      throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);
    }

    return { message: 'Authenticated successfully' };
  }
}

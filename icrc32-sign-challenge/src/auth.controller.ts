import { Controller, Post, Body } from '@nestjs/common';
import { AuthService, RequestVerify, ResponsetVerify } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('verify')
  verify(@Body() data: RequestVerify): ResponsetVerify {
    return this.authService.verifyAuth(data);
  }
}

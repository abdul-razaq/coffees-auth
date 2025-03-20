import {
  ConflictException,
  Injectable,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { OAuth2Client, TokenPayload } from 'google-auth-library';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { AuthenticationService } from '../authentication.service';

@Injectable()
export class GoogleAuthenticationService implements OnModuleInit {
  private oauth2Client: OAuth2Client;

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthenticationService,
    @InjectRepository(User) private readonly userRespository: Repository<User>,
  ) {}
  onModuleInit() {
    const clientId = this.configService.get('GOOGLE_AUTHENTICATION_CLIENT_ID');
    const clientSecret = this.configService.get(
      'GOOGLE_AUTHENTICATION_CLIENT_SECRET',
    );

    this.oauth2Client = new OAuth2Client({
      clientId,
      clientSecret,
    });
  }

  public async authenticate(token: string) {
    try {
      const loginTicket = await this.oauth2Client.verifyIdToken({
        idToken: token,
      });

      const tokenPayload = loginTicket.getPayload();
      const { email, sub: googleId } = tokenPayload as TokenPayload;

      const existingUser = await this.userRespository.findOneBy({ googleId });
      if (existingUser) {
        return this.authService.generateTokens(existingUser);
      } else {
        const newUser = await this.userRespository.save({ email, googleId });
        return this.authService.generateTokens(newUser);
      }
    } catch (error) {
      const pgUniqueViolationErrorCode = '23505';
      if (error.code === pgUniqueViolationErrorCode) {
        throw new ConflictException();
      }
      throw new UnauthorizedException();
    }
  }
}

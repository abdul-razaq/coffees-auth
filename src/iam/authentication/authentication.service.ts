import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import jwtConfig from '../config/jwt.config';
import { HashingService } from '../hashing/hashing.service';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly usersRespository: Repository<User>,
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService,
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
  ) {}

  async signUp(signUpDto: SignUpDto) {
    try {
      const user = new User();
      user.email = signUpDto.email;
      user.password = await this.hashingService.hash(signUpDto.password);

      await this.usersRespository.save(user);
    } catch (error) {
      const pgUniqueViolationErrorCode = '23505';
      if (error.code === pgUniqueViolationErrorCode) {
        throw new ConflictException();
      }
      throw error;
    }
  }

  async signIn(signInDto: SignInDto) {
    const existingUser = await this.usersRespository.findOneBy({
      email: signInDto.email,
    });

    if (!existingUser) {
      throw new UnauthorizedException('User does not exist');
    }

    const passwordIsEqual = await this.hashingService.compare(
      signInDto.password,
      existingUser.password,
    );

    if (!passwordIsEqual) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return await this.generateTokens(existingUser);
  }

  public async refreshToken(refreshTokenDto: RefreshTokenDto) {
    try {
      const { sub } = await this.jwtService.verifyAsync<
        Pick<ActiveUserData, 'sub'>
      >(refreshTokenDto.refresh_token, {
        issuer: this.jwtConfiguration.issuer,
        audience: this.jwtConfiguration.audience,
        secret: this.jwtConfiguration.secret,
      });

      const existingUser = await this.usersRespository.findOneByOrFail({
        id: sub,
      });

      return await this.generateTokens(existingUser);
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  public async generateTokens(existingUser: User) {
    const [accessToken, refreshToken] = await Promise.all([
      this.signToken<Partial<ActiveUserData>>(
        existingUser.id,
        this.jwtConfiguration.accessTokenTtl,
        { email: existingUser.email },
      ),
      this.signToken(existingUser.id, this.jwtConfiguration.refreshTokenTtl),
    ]);

    return { accessToken, refreshToken };
  }

  private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
    return await this.jwtService.signAsync(
      {
        sub: userId,
        ...payload,
      } as ActiveUserData,
      {
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
        secret: this.jwtConfiguration.secret,
        expiresIn,
      },
    );
  }
}

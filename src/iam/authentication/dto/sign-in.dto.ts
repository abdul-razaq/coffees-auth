import { IsNumberString, IsOptional } from 'class-validator';
import { SignUpDto } from './sign-up.dto';

export class SignInDto extends SignUpDto {
  @IsOptional()
  @IsNumberString()
  tfaCode?: string;
}

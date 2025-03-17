import {IsAlphanumeric, IsOptional, IsString, MaxLength, MinLength, IsNotEmpty, IsEmail} from 'class-validator';
import {Transform, TransformFnParams} from "class-transformer";

export class CreateWorkspaceDto {
  @MinLength(4)
  @MaxLength(64)
  @IsString()
  @Transform(({ value }: TransformFnParams) => value?.trim())
  name: string;

  @IsOptional()
  @MinLength(4)
  @MaxLength(30)
  @IsAlphanumeric()
  hostname?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Email must be an email' })
  email: string;


  organization?: string;
  logo?: string;

}

import { forwardRef, Module } from '@nestjs/common';
import { SearchController } from './search.controller';
import { SearchService } from './search.service';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';

@Module({
  imports: [
  forwardRef(() => AuthModule),
  forwardRef(() => UserModule),
]
,
  controllers: [SearchController],
  providers: [SearchService],
})
export class SearchModule {}

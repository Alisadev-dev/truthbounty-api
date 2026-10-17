import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Public } from '../decorators/public.decorator';
import { CreateSupportRequestDto } from './dto/create-support-request.dto';
import { SupportRequestService } from './support.service';

@ApiTags('support')
@Controller('support')
export class SupportController {
  constructor(private readonly supportService: SupportRequestService) {}

  @Public()
  @Post('requests')
  @ApiOperation({
    summary: 'Submit a privacy-safe support request',
    description:
      'Accepts minimal support data while rejecting secrets, private keys, and non-public evidence before storage.',
  })
  @ApiResponse({ status: 201, description: 'Support request accepted' })
  createSupportRequest(@Body() dto: CreateSupportRequestDto) {
    return this.supportService.createSupportRequest(dto);
  }

  @Public()
  @Get('requests')
  @ApiOperation({ summary: 'List retained support requests' })
  @ApiQuery({ name: 'contact', required: false })
  listSupportRequests(@Query('contact') contact?: string) {
    const requests = this.supportService.listSupportRequests();
    if (!contact) return requests;
    return requests.filter((record) => record.contact === contact);
  }

  @Public()
  @Get('requests/:id')
  @ApiOperation({ summary: 'Fetch a support request by id' })
  getSupportRequest(@Param('id') id: string) {
    return this.supportService.getSupportRequest(id);
  }

  @Public()
  @Delete('requests/:id')
  @ApiOperation({ summary: 'Delete or expire a support request' })
  deleteSupportRequest(@Param('id') id: string) {
    const request = this.supportService.getSupportRequest(id);
    if (!request) return { deleted: false, id };

    this.supportService.cleanupExpiredSupportRequests();
    return { deleted: true, id, reference: request.reference };
  }
}
